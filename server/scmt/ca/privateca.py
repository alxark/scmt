import json
import subprocess
import os
import shutil
import base64
import binascii
import time
import hashlib
import re
import copy
from baseca import BaseCA

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2


class PrivateCA(BaseCA):
    account_key_size = 4096

    def __init__(self, domain, options, storage):
        BaseCA.__init__(self, domain, options, storage)

        self.key = options['key'] if 'key' in options else self._dir + '/ca.pem'
        self.cert = options['cert'] if 'cert' in options else self._dir + '/cert.pem'
        self.days = 365 if 'days' not in options else options['days']
        self.openssl_config = options['openssl_config'] if 'openssl_config' in options else ''

        self.subject = options['subject']

        self.log("Initialize PrivateCA, key: %s" % self.key)

    def issue_certificate(self, hostname, force=False):
        tmp_dir = self.tmp_dir + '/' + hostname + '/generate'
        self.log("Issue cert for %s, tmp_path: %s" % (hostname, tmp_dir))
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

        tmp_openssl = tmp_dir + '/openssl.cnf'

        self.get_csr(hostname)

        tmp_crt_path = self.get_temp_path()
        tmp_csr_path = self.copy_to_fs(self.get_csr_url(hostname))

        sign_command = [
            "openssl",
            "ca",
            "-days", str(self.days),
            "-notext",
            "-md", "sha256",
            "-in", tmp_csr_path,
            "-out", tmp_crt_path,
            "-outdir", tmp_dir,
            "-keyfile", self.key,
            "-cert", self.cert,
            "-batch",
            '-config', tmp_openssl
        ]

        self.log("Running sign command: %s" % " ".join(sign_command))

        with open(self.openssl_config, 'r') as openssl_template:
            with open(tmp_openssl, 'w') as openssl_result:
                openssl_result.write(openssl_template.read().replace('%KEY_DIR%', tmp_dir))

        with open(tmp_dir + '/index.txt', 'w') as index_txt:
            index_txt.write("")

        with open(tmp_dir + '/serial', 'w') as serial:
            serial.write('00')

        cmd = subprocess.Popen(sign_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        exit_code = cmd.wait()

        result = cmd.stdout.readlines()
        self.log("OpenSSL sign completed for %s" % hostname)
        if exit_code != 0:
            raise RuntimeError("Wrong OpenSSL result code. Got: %d, result: %s" % (exit_code, str(result)))

        if not os.path.isfile(tmp_crt_path):
            raise RuntimeError("Failed to sign certificate for %s, error: %s" % (hostname, str(result)))

        self.copy_to_storage(tmp_crt_path, self.get_crt_url(hostname), delete=False)
        self.copy_to_storage(tmp_crt_path, self.get_fullchain_url(hostname))

        shutil.rmtree(tmp_dir)
        self.log("Certificate successfully generated for %s" % hostname)

    def get_cert_subject(self, hostname):
        return self.subject.replace('%COMMONNAME%', hostname)
