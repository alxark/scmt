import loggable
import os
from letsencrypt import LetsEncrypt
from hooks.cloudflare import Cloudflare
import threading
import time


class Manager(loggable.Loggable, threading.Thread):
    def __init__(self, dir, domains):
        self.log("Initializing manager")
        self._dir = dir
        self._locks = {}
        self._queueLock = threading.Lock()
        self._queue = []
        self._is_active = True

        if not os.path.exists(self._dir):
            os.makedirs(self._dir)
            self.log("Creating path %s" % self._dir)
        self._domains = {}
        for domain in domains:
            self._domains[domain] = self.init_domain(domain, domains[domain])
            self._locks[domain] = threading.Lock()

        threading.Thread.__init__(self)

    def init_domain(self, domain, config):
        if 'ca' not in config or config['ca'] not in ['letsencrypt']:
            raise RuntimeError("Failed to initialize domain %s, no CA or wrong CA type" % domain)

        config['dir'] = self._dir + '/' + domain
        if not os.path.exists(config['dir']):
            os.makedirs(config['dir'])

        if config['ca'] == 'letsencrypt':
            ca = LetsEncrypt(config)
        else:
            raise RuntimeError("Wrong CA name for %s, CA %s is unacceptable" % (domain, config['ca']))

        if 'hook' in config:
            hook_opts = {}
            for opt in config.keys():
                if opt[:5] != 'hook.':
                    continue
                hook_opts[opt[5:]] = config[opt]

            if config['hook'] == 'cloudflare':
                hook = Cloudflare(hook_opts)
            ca.set_hook(hook)

        self.log("Initialized domain %s" % domain)
        return ca

    def run(self):
        self.log("Starting new manager thread")
        while self._is_active:
            for zone in self._domains:
                self._domains[zone].cleanup_certificates()

            hostname = self.get_from_queue()
            if not hostname:
                time.sleep(10)
                continue

            ca = self.get_ca(hostname)
            try:
                ca.issue_certificate(hostname)
            except RuntimeError as e:
                self.log("Failed to issue certificate for %s, got error: %s" % (hostname, e.message))

    def add_to_queue(self, hostname):
        with self._queueLock:
            if hostname not in self._queue:
                self.log("Added new task for queue: %s" % hostname)
                self._queue.append(hostname)

    def get_from_queue(self):
        with self._queueLock:
            if len(self._queue) == 0:
                return None

            hostname = self._queue.pop(0)

        return hostname

    def test(self):
        return {'sdfsdf': 1, 'sdfsss':2}

    def get_ca(self, hostname):
        for domain in self._domains.keys():
            if hostname[-len(domain)-1:] != '.' + domain:
                continue
            return self._domains[domain]

        raise RuntimeError("Failed to detect CA for %s" % domain)

    def get_key(self, req):
        """
        Generate new key for account

        :param req:
        :return:
        """
        key = self.get_ca(req['hostname']).generate_key(req['hostname'], req['algo'], int(req['bits']))
        return {'key': key}

    def get_key_path(self, hostname):
        return self.get_ca(hostname).get_key_path(hostname)

    def get_fullchain_path(self, hostname):
        return self.get_ca(hostname).get_fullchain_path(hostname)

    def cert(self, req):
        """
        Check if this certificate exists

        :param req:
        :return:
        """
        hostname = req['hostname']
        ip = req['ip']
        ca = self.get_ca(hostname)

        self.log("Certificate request from %s for %s" % (ip, hostname))

        if not ca.certificate_exists(hostname):
            self.add_to_queue(hostname)
            return {'status': 'pending'}

        cert = ca.get_cert(hostname, ip)
        chain = ca.get_full_chain(hostname)
        return {
            'status': 'available',
            'cert': cert,
            'fullchain': chain
        }



    def request_key(self, hostname):
        pass