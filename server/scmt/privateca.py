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
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2


class PrivateCA(BaseCA):
    account_key_size = 4096

    def __init__(self, options):
        BaseCA.__init__(self, options)

        self.key = options['key'] if 'key' in options else self._dir + '/ca.pem'
        self.cert = options['cert'] if 'cert' in options else self._dir + '/cert.pem'
        self.days = 365 if 'days' not in options else options['days']
        self.openssl_config = options['openssl_config'] if 'openssl_config' in options else ''

        self.subject = options['subject']

        self.log("Initialize PrivateCA, key: %s" % self.key)

    def issue_certificate(self, hostname):
        self.log("Issue cert for %s" % hostname)

        csr = self.get_csr(hostname)
        tmp_dir = self._dir + '/' + hostname + '/generate'
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

        tmp_openssl = tmp_dir + '/openssl.cnf'

        sign_command = [
            "openssl",
            "ca",
            "-days", str(self.days),
            "-notext",
            "-md", "sha256",
            "-in", csr,
            "-out", self._dir + "/cert.pem",
            "-outdir", tmp_dir,
            "-keyfile", self.key,
            "-cert", self.cert,
            "-batch",
            '-config', tmp_openssl
        ]

        with open(self.openssl_config, 'r') as openssl_template:
            with open(tmp_openssl, 'w') as openssl_result:
                openssl_result.write(openssl_template.read().replace('%KEY_DIR%', tmp_dir))

        with open(tmp_dir + '/index.txt', 'w') as index_txt:
            index_txt.write("")

        with open(tmp_dir + '/serial', 'w') as serial:
            serial.write('00')

        cmd = subprocess.Popen(sign_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = cmd.wait()

        result = cmd.stdout.readlines()
        if not os.path.exists(tmp_dir + '/00.pem'):
            raise RuntimeError("Failed to sign certificate for %s" % hostname)

        with open(tmp_dir + '/00.pem', 'r') as cert_file:
            cert = cert_file.read()

            for path in [self._dir + '/' + hostname + '/cert.pem', self._dir + '/' + hostname + '/fullchain.pem']:
                with open(path, 'w') as output:
                    output.write(cert)

        shutil.rmtree(tmp_dir)
        self.log("Certificate successfully generated for %s" % hostname)

        #self.log("".join(result))

    def get_cert_subject(self, hostname):
        return self.subject.replace('%COMMONNAME%', hostname)
