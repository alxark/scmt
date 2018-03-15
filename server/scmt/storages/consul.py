import requests


class Consul:
    def __init__(self, consul_addr = '172.17.0.1:8500', logger = None):
        self.consul_addr = consul_addr
        self.logger = logger

    def log(self, msg):
        if self.logger:
            self.logger.log(msg)

    def list(self, path):
        url = 'http://%s/v1/kv/%s?keys' % (self.consul_addr, path)
        self.log('[CONSUL] GET %s' % url)

