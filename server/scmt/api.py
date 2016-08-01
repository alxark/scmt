import loggable
import BaseHTTPServer
import socket
import sys
import SocketServer
import SimpleHTTPServer
from SocketServer import ThreadingMixIn
import os
import threading
import json
import time
import ssl


class _ScmtHandler(SimpleHTTPServer.SimpleHTTPRequestHandler, loggable.Loggable):
    # client IP detected by headers or directly
    client_ip = '127.0.0.1'
    answer = False
    methods = ['sign', 'key', 'cert']

    def json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        self.wfile.write(json.dumps(data))

    def error(self, code, error):
        self.log("[%s] Error: %s (%s)" % (self.client_address[0], str(code), error))
        return self.json({'code': code, 'error': error}, code)

    def do_GET(self):
        return self.json({'ok': 1})

    def do_POST(self):
        if 'Content-Length' not in self.headers or int(self.headers['Content-Length']) == 0:
            return self.error(500, 'bad_content_length')

        try:
            req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        except IOError:
            return self.error(500, 'failed_to_parse_request_body')

        if 'type' not in req:
            return self.error(500, 'unknown_request_type')

        if req['type'] not in self.methods:
            return self.error(500, 'unacceptable_request_method')

        req['ip'] = self.client_address[0]

        return getattr(self, req['type'] + '_call')(req)

    def key_call(self, req):
        """
        Generate key for certificate on server side, used in case
        when we want to have same certificate on serveral servers and keep this key in one place

        :param req:
        :return:
        """
        if 'bits' not in req:
            return self.error(500, 'key_bits_should_be_specified')
        if 'hostname' not in req:
            return self.error(500, 'key_hostname_should_be_specified')
        if 'algo' not in req or req['algo'] not in self.server.manager.get_supported_keys_algo(req['hostname']):
            return self.error(500, 'empty_or_incorrect_algo')

        try:
            result = self.server.manager.get_key(req)
        except RuntimeError:
            return self.json({'code': 500, 'error': 'failed_to_generate_key'})

        result['code'] = 200
        return self.json(result, 200)

    def cert_call(self, req):
        if 'hostname' not in req:
            return self.json({'code': 500, 'error': 'no_hostname_specified'})

        return self.json(self.server.manager.cert(req), 200)

    def log_message(self, format, *args):
        pass


class _ScmtApi(ThreadingMixIn, BaseHTTPServer.HTTPServer, loggable.Loggable):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, manager=False):
        self.manager = manager
        BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

    def finish(self, *args, **kw):
        try:
            if not self.wfile.closed:
                self.wfile.flush()
                self.wfile.close()
        except socket.error:
            self.log("""Exception: %s""" % sys.exc_info()[1])
            pass

        self.rfile.close()


class Api(loggable.Loggable, threading.Thread):
    def __init__(self, manager, port, ssl=None):
        self.manager = manager
        self.port = port
        self.host = '0.0.0.0'
        self.ssl = ssl

        threading.Thread.__init__(self)

    def is_running(self):
        return True

    def run(self):
        """
        Start HTTP daemon
        """


        self.log("Starting new API instance on %d" % self.port)
        http_handler = _ScmtHandler
        SocketServer.TCPServer.allow_reuse_address = True

        http_service = _ScmtApi((self.host, self.port), http_handler, manager=self.manager)

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