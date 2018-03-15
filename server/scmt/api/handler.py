import SimpleHTTPServer
import json
import re


class Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    # client IP detected by headers or directly
    client_ip = '127.0.0.1'
    answer = False
    methods = ['sign', 'key', 'cert']

    def json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        self.wfile.write(json.dumps(data))

    def log(self, msg):
        pass

    def error(self, code, error):
        self.log("[%s] Error: %s (%s)" % (self.client_address[0], str(code), error))
        return self.json({'code': code, 'error': error}, code)

    def do_GET(self):
        return self.json({'ok': 1})

    def get_client_ip(self):
        if 'X-Real-IP' in self.headers:
            ip = re.sub('/[^a-f0-9\.]/', '', self.headers['X-Real-IP'])
            if len(ip) == 0 or ip != self.headers['X-Real-IP']:
                return '127.0.0.1'

            return ip

        return self.client_address[0]

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

        req['ip'] = self.get_client_ip()

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
        except RuntimeError as e:
            return self.json({'code': 500, 'error': 'failed_to_generate_key', 'debug': e.message})

        result['code'] = 200
        return self.json(result, 200)

    def cert_call(self, req):
        if 'hostname' not in req:
            return self.json({'code': 500, 'error': 'no_hostname_specified'})

        return self.json(self.server.manager.cert(req), 200)

    def log_message(self, format, *args):
        pass