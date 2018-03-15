#!/usr/bin/python

import ConfigParser
import urllib2
import urllib
import json
import sys
import json
import syslog
import time
import random
import subprocess
import os
import hashlib


def log(msg):
    print(time.strftime('%Y/%m/%d %H:%M ') + msg)


class CertLoader:
    def load_certs(self, services):
        res = True
        for service in services:
            if not self.load_service_certs(service, services[service]):
                log("Failed to load cert for %s" % service)
                res = False

        return res

    def blocking_load(self, services, timeout):
        start = time.time()
        loaded = []

        while start > time.time() - timeout:
            all_loaded = True
            for service in services:
                if service in loaded:
                    continue

                if not self.load_service_certs(service, services[service]):
                    all_loaded = False
                    log("Failed to load cert for %s" % service)
                    continue

                loaded.append(service)

            if all_loaded:
                return True

            log("Failed to load all certs. Sleep for some time")
            time.sleep(15)

        log("Failed to load all certs")
        return False

    def load_service_certs(self, service, service_info):
        hostname = service_info['hostname']
        key = service_info['key']
        cert = service_info['cert']

        if 'algo' in service_info:
            algo = service_info['algo']
        else:
            algo = 'RSA'

        if 'outform' in service_info:
            outform = service_info['outform']
        else:
            outform = 'pem'

        if 'trigger' in service_info:
            trigger = service_info['trigger']
        else:
            trigger = None

        generator = service_info['generator']
        log("Working on %s/%s from %s" % (service, hostname, generator))

        req = {
            "type": "key",
            "bits": 2048,
            "hostname": hostname,
            "algo": algo,
        }

        link = urllib2.urlopen(generator + '/call', json.dumps(req), timeout=20)
        backend_answer = link.read().rstrip()

        log("Received backend answer")
        try:
            info = json.loads(backend_answer)
        except ValueError:
            return False

        if 'key' not in info:
            log("no key found, reply: %s" % backend_answer)
            return False

        if not os.path.exists(os.path.dirname(key)):
            log("Create directory to store key file")
            os.makedirs(os.path.dirname(key))

        with open(key, 'w') as key_out:
            key_out.write(info['key'])

        req = {
            "type": "cert",
            "hostname": hostname
        }

        link = urllib2.urlopen(generator + '/call', json.dumps(req), timeout=20)
        backend_answer = link.read().rstrip()

        try:
            cert_info = json.loads(backend_answer)
        except ValueError:
            log("failed to parse cert request")
            return False

        if 'status' not in cert_info:
            log("No status info found")
            return False

        if 'fullchain' not in cert_info:
            log("No fullchain found in reply")
            return False

        if cert_info['status'] == 'available':
            updated = False
            old_hash = ''
            if not os.path.exists(cert):
                updated = True
            else:
                with open(cert, 'r') as old_cert:
                    h = hashlib.md5()
                    h.update(old_cert.read())
                    old_hash = h.hexdigest()

            if outform == 'der':
                tmpFile = "/tmp/crt-%s" % (str(random.random()))
                with open(tmpFile, 'w') as cert_out:
                    cert_out.write(cert_info['fullchain'])
                    log("cert saved to temporary path for converting. path: %s" % tmpFile)

                cmd = ["openssl", "x509", "-in", tmpFile, "-out", cert, "-inform", "pem", "-outform", "der"]
                log("Running: " + " ".join(cmd))
                convert = subprocess.Popen(cmd)

                res = convert.wait()
                if res != 0:
                    log("Failed to convert cert to DER format, exitcode: %d" % res)
            else:
                with open(cert, 'w') as cert_out:
                    cert_out.write(cert_info['fullchain'])
                    log("cert info updated in %s" % cert)
            if not os.path.exists(os.path.dirname(cert)):
                os.makedirs(os.path.dirname(cert))

            with open(cert, 'r') as new_cert:
                h = hashlib.md5()
                h.update(new_cert.read())
                new_hash = h.hexdigest()

                if new_hash != old_hash and trigger:
                    log("Hash changed %s => %s" % (old_hash, new_hash))

                    log("Running trigger command: %s" % trigger)
                    tr = subprocess.Popen(trigger, shell=True)

                    res = tr.wait()
                    if res != 0:
                        log("failed to executed trigger command, got : %d" % res)

            return True
        else:
            log("cert status is %s" % cert_info['status'])
            return False


LOAD_TIMEOUT = 500

parser = ConfigParser.ConfigParser()
parser.read('/etc/scmt-client.ini')

sections = parser.sections()

services = {}

for service_name in sections:
    options = parser.options(service_name)

    services[service_name] = {}
    for opt in options:
        services[service_name][opt] = parser.get(service_name, opt)

loader = CertLoader()
if '-once' in sys.argv:
    log("Downloading certificates first time")
    loader.blocking_load(services, LOAD_TIMEOUT)
    sys.exit(0)

log("Starting scmt daemon process")
while True:
    log("Starting download process")
    try:
        loader.blocking_load(services, LOAD_TIMEOUT)
    except:
        log("Failed to download certs")
        time.sleep(3600)
        continue

    time.sleep(43200)
