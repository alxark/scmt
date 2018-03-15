import os
import subprocess
import base64
import textwrap
import datetime
import time
import threading
import shutil
import re
import random

try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2


class BaseCA:
    def __init__(self, domain, options, storage):
        self._domain = domain
        self._fs_lock = threading.Lock()

        if 'dir' in options:
            self._dir = options['dir']
        if 'certificate_expiration' in options:
            self._certificate_expiration = int(options['certificate_expiration'])
        else:
            self._certificate_expiration = 86400 * 14

        if 'tmp' in options:
            self.tmp_dir = options['tmp']
        else:
            self.tmp_dir = '/tmp/scmt'

        if not os.path.isdir(self.tmp_dir):
            self.log("Creating tmp dir %s" % self.tmp_dir)
            os.mkdir(self.tmp_dir)

        if 'request_cleanup' in options:
            self._request_cleanup = int(options['request_cleanup'])
        else:
            self._request_cleanup = 2592000

        self._storage = storage

    def get_temp_path(self):
        chunk = str(int(time.time() / 30))
        path = str(random.random()) + str(time.time())
        chunk_dir = self.tmp_dir + '/' + chunk

        with self._fs_lock:
            if not os.path.isdir(chunk_dir):
                os.mkdir(chunk_dir)
                self._cleanup_temp_path()

        return chunk_dir + '/' + path

    def _cleanup_temp_path(self):
        allowed_chunks = [str(int(time.time() / 30)), str(int(time.time() / 30) - 1)]
        for chunk in os.listdir(self.tmp_dir + '/'):
            if chunk not in allowed_chunks:
                shutil.rmtree(self.tmp_dir + '/' + chunk)

    def log(self, msg, level='info'):
        thread_name = threading.currentThread().name
        print(time.strftime('%Y/%m/%d %R ', time.localtime()) + '[' + thread_name + '] [' + level + '] ' + msg.strip())

    def generate_key(self, hostname, algo, bits):
        """
        Generate host private key

        :param hostname:
        :param algo:
        :param bits:
        :return:
        """

        path = self._domain + '/' + hostname + '/key.pem'
        key_tmp_path = self.get_temp_path()

        if self._storage.exists(path):
            return self._storage.read(path)

        self.log("Generating new key in %s, algo: %s, temp-file: %s" % (path, algo, key_tmp_path))
        if algo == 'RSA':
            generate_cmd = ['openssl', 'genrsa', '-out', key_tmp_path, str(bits)]
        elif algo == 'EC-SECP384R1':
            generate_cmd = ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out', key_tmp_path, '-noout']

        cmd = subprocess.Popen(generate_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = cmd.wait()
        if res != 0:
            raise RuntimeError("Failed to generate host key, host: %s" % hostname)

        with open(key_tmp_path, 'r') as old_key:
            key = old_key.read()

        self._storage.write(path, key)
        os.unlink(key_tmp_path)

        return key

    def get_key_path(self, hostname):
        return self.copy_to_fs(self.get_key_url(hostname))

    def get_fullchain_path(self, hostname):
        return self.copy_to_fs(self.get_fullchain_url(hostname))

    def get_csr_path(self, hostname):
        return self.copy_to_fs(self.get_csr_url(hostname))

    def copy_to_fs(self, path):
        """
        Copy data from storage to temp file

        :param path:
        :return:
        """
        temp_path = self.get_temp_path()
        with open(temp_path, 'w') as out:
            out.write(self._storage.read(path))

        return temp_path

    def copy_to_storage(self, temp_path, path, delete=True):
        with open(temp_path, 'r') as src:
            data = src.read()

            self._storage.write(path, data)

        if delete:
            os.unlink(temp_path)

    def certificate_exists(self, hostname, ip=None):
        #if ip:
            # self.register_request(hostname, ip)

        return self._storage.exists(self.get_fullchain_url(hostname))

    def get_key_url(self, hostname):
        return self._domain + '/' + hostname + '/key.pem'

    def get_csr_url(self, hostname):
        return self._domain + '/' + hostname + '/request.csr'

    def get_crt_url(self, hostname):
        return self._domain + '/' + hostname + '/cert.pem'

    def get_fullchain_url(self, hostname):
        return self._domain + '/' + hostname + '/fullchain.pem'

    def get_request_url(self, hostname, ip):
        return self._domain + '/' + hostname + '/requests/' + ip

    def get_cert(self, hostname, ip=None, allow_old=False):
        if ip:
            self.register_request(hostname, ip)

        try:
            return self._storage.read(self.get_crt_url(hostname))
        except IndexError:
            return None

    def register_request(self, hostname, ip):
        """
        Register request from specific IP for some SSL host, used to automatic remove
        of old and unused hosts
        """
        ip = re.sub('[^0-9a-zA-Z]', '_', ip)
        self.log("Request for %s IP: %s registered" % (hostname, ip))
        self._storage.write(self.get_request_url(hostname, ip), str(time.time()))

    def have_requests(self, hostname):
        requests_dir = self._domain + '/' + hostname + '/requests'

        try:
            ips = self._storage.list(requests_dir)
            return len(ips)
        except IndexError:
            return 0

    def cleanup_requests(self, hostname):
        """
        Cleanup host requests history, removes expired requests logs

        :param hostname:
        :return:
        """
        requests_path = self._domain + '/' + hostname + '/requests'
        try:
            requests_hosts = self._storage.list(requests_path)
        except IndexError:
            return True

        for ip in requests_hosts:
            try:
                timestamp = float(self._storage.read(requests_path + '/' + ip))
            except IndexError:
                continue

            if timestamp < time.time() - self._request_cleanup:
                self._storage.delete(requests_path + '/' + ip)
                self.log("No requests for %s from IP %s for %d days" % (hostname, ip, (time.time() - timestamp) / 86400))

    def get_full_chain(self, hostname, force_reload=False):
        """
        Get all certificates in chain
        """

        if self._storage.exists(self.get_fullchain_url(hostname)) and not force_reload:
            return self._storage.read(self.get_fullchain_url(hostname))

        self.log("Loading certificate chain for %s" % hostname)
        chain = (self.build_chain(self.get_cert(hostname)))

        self._storage.write(self.get_fullchain_url(hostname), chain)
        self.log("Full-chain saved to %s" % self.get_fullchain_url(hostname))

        return chain

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
        """
        Read info from PEM encoded certificate

        :param crt:
        :return:
        """
        run = ["openssl", "x509", "-text", "-noout"]
        cmd = subprocess.Popen(run, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        response = cmd.communicate(crt)

        lines = response[0].split("\n")
        res = None
        while True:
            res = cmd.poll()
            if res is not None:
                break

        if res != 0:
            return None

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

    def get_csr(self, hostname):
        """
        Get CSR path of certificate, if it's not available then generate it

        :param hostname:
        :return:
        """
        if self._storage.exists(self.get_csr_url(hostname)):
            return self._storage.read(self.get_csr_url(hostname))

        csr_temp_path = self.get_temp_path()
        key_temp_path = self.copy_to_fs(self.get_key_url(hostname))

        self.log("Generating new CSR request for %s, output %s" % (hostname, csr_temp_path))
        generate_command = ["openssl", "req", "-key", key_temp_path, "-new", "-out", csr_temp_path, "-subj", "/CN=" + self.get_cert_subject(hostname)]
        self.log("Running: %s" % " ".join(generate_command))

        cmd = subprocess.Popen(generate_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        exit_code = cmd.wait()

        result = cmd.stdout.readlines()

        if exit_code != 0:
            raise RuntimeError("Failed to create certificate request. Exited: %d. Reply: %s" % (exit_code, result))

        self.copy_to_storage(csr_temp_path, self.get_csr_url(hostname))

        return self._storage.read(self.get_csr_url(hostname))

    def get_cert_subject(self, hostname):
        """
        Generate subject for certificate request

        :param hostname:
        :return:
        """
        return "/CN=" + hostname

    def cleanup_certificates(self):
        """
        Remove old and unused certificates, update expired certificates

        :return:
        """

        self.log("Running clean-up for %s" % self._domain)
        try:
            hostnames = self._storage.list(self._domain)
        except IndexError:
            return True

        self.log("Total number of domains: %d" % len(hostnames))
        for hostname in hostnames:
            self.cleanup_requests(hostname)
            requests = self.have_requests(hostname)

            if not self.have_requests(hostname):
                self.log("Certificates for %s is not needed anymore, deleting it" % hostname)
                self._storage.delete(self._domain + '/' + hostname)

            cert = self.get_cert(hostname)
            if not cert:
                continue

            info = self.get_cert_info(cert)

            self.log("%s expiration time %s, requests: %d" % (hostname, info['NotAfter'].strftime('%Y/%m/%d'), requests), level='debug')
            if int(info['NotAfter'].strftime('%s')) - time.time() < self._certificate_expiration:
                self.log("Certificate for %s need to be renewed" % hostname)
                try:
                    self.issue_certificate(hostname, force=True)
                except RuntimeError:
                    self.log("Failed to issue new certificate for %s" % hostname)

        self.log("Clean-up for %s finished." % self._domain)

    def issue_certificate(self, hostname):
        """
        This method should be redefined in child classes and will issue certificate for real

        :param hostname:
        :return:
        """
        pass


    def set_hook(self, hook):
        self._hook = hook