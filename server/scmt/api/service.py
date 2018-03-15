import BaseHTTPServer
import socket
import sys
import SocketServer
import threading
from handler import Handler
from server import Server as ApiServer
import time
import ssl


class Service(threading.Thread):
    def __init__(self, manager, port, ssl=None):
        self.manager = manager
        self.port = port
        self.host = '0.0.0.0'
        self.ssl = ssl

        threading.Thread.__init__(self)

    def log(self, msg):
        pass

    def is_running(self):
        return True

    def run(self):
        """
        Start HTTP daemon
        """
        self.log("Starting new API instance on %d" % self.port)
        http_handler = Handler
        SocketServer.TCPServer.allow_reuse_address = True

        try:
            http_service = ApiServer((self.host, self.port), http_handler, manager=self.manager)
        except socket.error as e:
            self.log("Failed to bind to port. Got: %s" % str(e))
            return False

        if self.ssl:
            self.manager.get_key({'hostname': self.ssl, 'algo': 'RSA', 'bits': 2048})
            key_path = self.manager.get_key_path(self.ssl)

            while True:
                res = self.manager.cert({'hostname': self.ssl, 'ip': '127.0.0.1'})
                if res['status'] != 'available':
                    time.sleep(10)
                    continue

                self.log("Certificate successfully received for %s" % self.ssl)
                break

            cert_path = self.manager.get_fullchain_path(self.ssl)
            self.log("Key: %s, Cert: %s" % (key_path, cert_path))
            http_service.socket = ssl.wrap_socket(http_service.socket, keyfile=key_path, certfile=cert_path, server_side=True)

        self.log("HTTP API server started")
        while self.is_running():
            http_service.handle_request()