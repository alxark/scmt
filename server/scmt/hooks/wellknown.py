import requests
import time
import sys
import socket
import scmt.loggable
import threading

import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
from SocketServer import ThreadingMixIn


class WellKnownHttpHandler(SimpleHTTPServer.SimpleHTTPRequestHandler, scmt.loggable.Loggable):
    # client IP detected by headers or directly
    client_ip = '127.0.0.1'
    answer = False

    def do_GET(self):
        path_data = self.path.split("/")
        if path_data[1] != '.well-known':
            return self.fail()

        if path_data[2] == 'acme-test':
            return self.ok('available')

        token = path_data[-1]
        try:
            reply = self.server.hook.get_challenge(token)
        except IndexError:
            return self.fail()

        return self.ok(reply)

    def ok(self, msg):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        self.wfile.write(msg)

    def do_HEAD(self):
        return self.fail()

    def do_POST(self):
        return self.fail()

    def fail(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        self.wfile.write("No such file or directory. Request to %s is invalid" % self.path)


class WellKnownHttpApi(ThreadingMixIn, BaseHTTPServer.HTTPServer, scmt.loggable.Loggable):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, hook=False):
        self.hook = hook
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


class WellKnown(scmt.loggable.Loggable):
    challenges = {}

    def __init__(self, options):
        if 'port' not in options:
            raise RuntimeError("WellKnown Hook Error. Not found port, please specify hook.port in config")

        self._port = int(options['port'])

        self.log("WellKnown hook initialized, port: %d" % self._port)

        daemon_thread = threading.Thread(target=self.daemonize)
        daemon_thread.start()

    def daemonize(self):
        self.log("Started daemon thread for hook on port %d" % self._port)

        http_handler = WellKnownHttpHandler
        SocketServer.TCPServer.allow_reuse_address = True

        well_known_server = WellKnownHttpApi(('0.0.0.0', self._port), http_handler, hook=self)
        while True:
            well_known_server.handle_request()

    def deploy_challenge(self, domain, token, key_authorization):
        self.log("Challenge URL: http://%s/.well-known/acme-challenge/%s" % (domain, token))

        self.challenges[key_authorization.split(".")[0]] = {
            'domain': domain,
            'token': token,
            'key': key_authorization,
            'created': time.time()
        }

        self.log("New challenge for %s, token %s, key: %s" % (domain, token, key_authorization))

    def get_challenge(self, token):
        """

        :param token:
        :return:
        """
        self.log("Request for challenge %s" % token)
        if token not in self.challenges:
            raise IndexError("no such challenge %s" % token)

        return self.challenges[token]['key']

    def verify(self, domain):
        """
        Check if we can run this hook actions

        :return:
        """
        self.log("Cleanup is not needed for WellKnown hook for %s" % domain)
        return True

    def clean_challenge(self, domain, token):
        pass

    def get_challenge_type(self):
        return 'http-01'