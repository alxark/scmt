import os
import subprocess
import base64
import textwrap
import datetime
import time
import loggable
import re
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2


class BaseCA(loggable.Loggable):
    def __init__(self, options):
        if 'dir' in options:
            self._dir = options['dir']

        if 'request_cleanup' in options:
            self._request_cleanup = int(options['request_cleanup'])
        else:
            self._request_cleanup = 2592000

    def generate_key(self, hostname, algo, bits):
        path = self._dir + '/' + hostname + '/key.pem'
        if not os.path.exists(path):
            if not os.path.exists(self._dir + '/' + hostname):
                os.makedirs(self._dir + '/' + hostname)

            self.log("Generating new key in %s" % path)
            gencmd = ['openssl', 'genrsa', '-out', path, str(bits)]
            cmd = subprocess.Popen(gencmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            res = cmd.wait()
        else:
            self.log("Private key %s already exists, using it" % path)

        with open(path, 'r') as old_key:
            return old_key.read()

    def certificate_exists(self, hostname):
        path = self._dir + '/' + hostname + '/cert.pem'
        return os.path.exists(path)

    def get_cert(self, hostname, ip=None):
        crt_path = self._dir + '/' + hostname + '/cert.pem'
        if ip:
            self.register_request(hostname, ip)

        with open(crt_path, 'r') as crt:
            return crt.read()

    def register_request(self, hostname, ip):
        """
        Register request from specific IP for some SSL host, used to automatic remove
        of old and unused hosts
        """
        requests_dir = self._dir + '/' + hostname + '/requests'
        if not os.path.exists(requests_dir):
            os.makedirs(requests_dir)

        name = re.sub('[^0-9a-zA-Z]', '_', ip)
        with open(requests_dir + '/' + name, 'w') as stamp:
            stamp.write(str(time.time()))

    def have_requests(self, hostname):
        requests_dir = self._dir + '/' + hostname + '/requests'
        if not os.path.exists(requests_dir):
            return False

        return len(os.listdir(requests_dir)) > 0

    def cleanup_requests(self, hostname):
        requests_dir = self._dir + '/' + hostname + '/requests'
        if not os.path.exists(requests_dir):
            return True

        for ip in os.listdir(requests_dir):
            with open(requests_dir + '/' + ip, 'r') as ts:
                try:
                    timestamp = float(ts.read())
                except ValueError:
                    timestamp = 0

            if timestamp < time.time() - self._request_cleanup:
                os.unlink(requests_dir + '/' + ip)
                self.log("No requests for %s from IP %s for %d days" % (hostname, ip, (time.time() - timestamp) / 86400))

    def get_full_chain(self, hostname):
        chain_path = self._dir + '/' + hostname + '/fullchain.pem'
        if not os.path.exists(chain_path):
            self.log("Loading certificate chain for %s" % hostname)
            chain = (self.build_chain(self.get_cert(hostname)))
            with open(chain_path, 'w') as chain_out:
                chain_out.write(chain)
                self.log("Fullchain saved to %s" % chain_path)

        with open(chain_path, 'r') as chain_in:
            return chain_in.read()

    def build_chain(self, crt):
        info = self.get_cert_info(crt)
        if not info:
            return ''

        if not info['CaIssuer']:
            self.log("Final cert: %s" % info['Subject'])
            return crt

        self.log("Loading parent cert for %s, url: %s" % (info['Subject'], info['CaIssuer']))
        parent_cert_body = urlopen(info['CaIssuer']).read()

        return crt + self.build_chain(self.convert2pem(parent_cert_body))

    def convert2pem(self, crt):
        if crt[:27] == '-----BEGIN CERTIFICATE-----':
            return crt

        encoded = "\n".join(textwrap.wrap(base64.b64encode(crt)))
        return """-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n""" % encoded

    def get_cert_info(self, crt):
        run = ["openssl", "x509", "-text", "-noout"]
        cmd = subprocess.Popen(run, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        cmd.stdin.write(crt)
        res = cmd.wait()

        if res != 0:
            return None

        lines = cmd.stdout.readlines()
        info = {
            'NotBefore': False,
            'NotAfter': False,
            'CaIssuer': '',
            'Subject': ''
        }
        for x in range(0, len(lines) - 1):
            line = lines[x].strip()
            if line[:12] == 'CA Issuers -':
                info['CaIssuer'] = line[12:].replace('URI:', '').strip()
            elif line[:11] == 'Not Before:':
                info['NotBefore'] = datetime.datetime.strptime(line[12:].strip(), "%b %d %H:%M:%S %Y %Z")
            elif line[:11] == 'Not After :':
                info['NotAfter'] = datetime.datetime.strptime(line[12:].strip(), "%b %d %H:%M:%S %Y %Z")
            elif line[:8] == 'Subject:':
                info['Subject'] = line[8:].strip()

        return info

    def cleanup_certificates(self):
        for hostname in os.listdir(self._dir):
            if not os.path.isdir(self._dir + '/' + hostname):
                continue

            self.cleanup_requests(hostname)
            if not self.have_requests(hostname):
                self.log("Certificates for %s is not needed anymore, might be deleted" % hostname)


    def set_hook(self, hook):
        self._hook = hook