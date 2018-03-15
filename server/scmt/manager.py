import os
import threading
import time

import loggable
import sys
import socket
from hooks.cloudflare import Cloudflare
from ca.letsencrypt import LetsEncrypt
from ca.privateca import PrivateCA


class Manager(loggable.Loggable, threading.Thread):
    def __init__(self, dir, domains, storages):
        self.log("Initializing manager")

        self._dir = dir
        self._locks = {}
        self.queueLock = threading.Lock()
        self.queue = []
        self.is_active = True
        self.last_cleanup = 0

        if not os.path.exists(self._dir):
            os.makedirs(self._dir)
            self.log("Creating path %s" % self._dir)
        self.domains = {}

        for domain in domains:
            options = domains[domain]
            storage = options['storage']
            if storage not in storages:
                raise IndexError("Unknown storage %s for domain %s" % (storage, domain))

            try:
                self.domains[domain] = self.init_domain(domain, domains[domain], storages[storage])
            except IndexError:
                self.log("Failed to initialize domain: %s" % domain)
                continue

            self._locks[domain] = threading.Lock()

        threading.Thread.__init__(self)

    def init_domain(self, domain, config, storage):
        if 'ca' not in config or config['ca'] not in ['letsencrypt', 'privateca']:
            raise RuntimeError("Failed to initialize domain %s, no CA or wrong CA type" % domain)

        config['dir'] = self._dir + '/' + domain
        if not os.path.exists(config['dir']):
            os.makedirs(config['dir'])

        if config['ca'] == 'letsencrypt':
            ca = LetsEncrypt(domain, config, storage)
        elif config['ca'] == 'privateca':
            ca = PrivateCA(domain, config, storage)
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

            if not hook.verify(domain):
                raise RuntimeError("Hook verification failed for %s" % domain)

        self.log("Initialized domain %s" % domain)
        return ca

    def run(self):
        """
        Proceed certificate issue requests in separate thread

        :return:
        """
        self.log("Initialized manager thread")
        while self.is_active:
            if self.last_cleanup < time.time() - 3600:
                self.log("Starting certificates cleanup")
                self.last_cleanup = time.time()
                for zone in self.domains:
                    try:
                        self.domains[zone].cleanup_certificates()
                    except:
                        self.log("Failed to cleanup certificates %s" % str(sys.exc_info()))
                        pass

                self.log("Certificate cleanup finished")

            hostname = self.get_from_queue()
            if not hostname:
                time.sleep(10)
                continue

            ca = self.get_ca(hostname)
            try:
                ca.issue_certificate(hostname)
                # initial request
                ca.register_request(hostname, '127.0.0.1')
            except (RuntimeError, IndexError, IOError, socket.timeout) as e:
                self.log("Failed to issue certificate for %s, got error: %s" % (hostname, e.message))
                
        self.log("Manager thread stopped")

    def add_to_queue(self, hostname):
        with self.queueLock:
            if hostname not in self.queue:
                self.log("Added new task for queue: %s" % hostname)
                self.queue.append(hostname)

    def get_from_queue(self):
        with self.queueLock:
            if len(self.queue) == 0:
                return None

            hostname = self.queue.pop(0)

        return hostname

    def get_ca(self, hostname):
        for domain in self.domains.keys():
            if hostname[-len(domain)-1:] != '.' + domain and hostname != domain:
                continue

            return self.domains[domain]

        raise RuntimeError("Failed to detect CA for %s" % hostname)

    def get_key(self, req):
        """
        Generate new key for account

        :param req:
        :return:
        """
        key = self.get_ca(req['hostname']).generate_key(req['hostname'], req['algo'], int(req['bits']))
        return {'key': key}

    def get_supported_keys_algo(self, hostname):
        """
        Get list of support keys types for specific hostname

        :param hostname:
        :return:
        """

        return ['RSA', 'EC-SECP384R1']

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

        if not ca.certificate_exists(hostname, ip):
            self.log("Not found certificate for %s/IP: %s" % (hostname, ip))
            self.add_to_queue(hostname)
            return {'status': 'pending'}

        try:
            cert = ca.get_cert(hostname, ip)
            chain = ca.get_full_chain(hostname)
        except:
            self.log("Failed to get certificate. Got exception: %s" % str(sys.exc_info()))
            return {'status': 'pending'}

        return {
            'status': 'available',
            'cert': cert,
            'fullchain': chain
        }

    def request_key(self, hostname):
        pass