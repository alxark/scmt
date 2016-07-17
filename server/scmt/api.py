import loggable
import BaseHTTPServer
import socket
import sys
import SocketServer
import SimpleHTTPServer
import os
import threading
import json


class _ScmtHandler(SimpleHTTPServer.SimpleHTTPRequestHandler, loggable.Loggable):
    # client IP detected by headers or directly
    client_ip = '127.0.0.1'
    answer = False
    methods = ['sign', 'key', 'cert']

    def json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        #print(json.dumps(data))

        self.wfile.write(json.dumps(data))

    def do_GET(self):
        return self.json({'ok': 1})

    def do_POST(self):
        self.log("POST request found")
        if 'Content-Length' not in self.headers or int(self.headers['Content-Length']) == 0:
            return self.json({'code': 500, 'error': 'bad_content_length'}, 500)

        try:
            req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        except IOError:
            return self.json({'code': 500, 'error': 'failed_to_parse_request_body'}, 500)

        if 'type' not in req:
            return self.json({'code': 500, 'error': 'unknown_request_type'})

        if req['type'] not in self.methods:
            return self.json({'code': 500, 'error': 'unaceptable_request_method'}, 500)

        req['ip'] = self.client_ip

        return getattr(self, req['type'] + '_call')(req)

    def key_call(self, req):
        """
        Generate key for certificate on server side, used in case
        when we want to have same certificate on serveral servers and keep this key in one place

        :param req:
        :return:
        """
        if 'bits' not in req:
            return self.json({'code': 500, 'error': 'key_bits_should_be_specified'}, 500)
        if 'hostname' not in req:
            return self.json({'code': 500, 'error': 'key_hostname_should_be_specified'}, 500)
        if 'algo' not in req or req['algo'] not in ['RSA', 'ECDSA']:
            return self.json({'code': 500, 'error': 'empty_or_incorrect_algo'}, 500)

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


class _ScmtApi(BaseHTTPServer.HTTPServer, loggable.Loggable):
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
    def __init__(self, manager, port):
        self.manager = manager
        self.port = port
        self.host = '127.0.0.1'

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

        self.log("HTTP API server started")
        while self.is_running():
            http_service.handle_request()