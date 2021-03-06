import json
import subprocess
import os
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


class LetsEncrypt(BaseCA):
    account_key_size = 4096
    # for how long should we sleep when challenge is not ready
    _challenge_sleep = 20
    # challenge total timeout, after this time we consider that LetsEncrypt is down now and try
    # to update certificate later
    _challenge_timeout = 600

    def __init__(self, domain, options, storage):
        BaseCA.__init__(self, domain, options, storage)
        # when we was last time limited
        self._rate_limit_last = 0

        self._hook = False

        if 'key' in options:
            self.account_key = options['key']
        else:
            self.account_key = self._dir + '/account.pem'

        if 'url' not in options:
            self.ca = "https://acme-v01.api.letsencrypt.org"
        elif options['url'] == 'stage':
            self.ca = "https://acme-staging.api.letsencrypt.org"
        else:
            self.ca = options['url']

        self._challenge = None

        if os.path.exists(self.account_key):
            self.log("LetsEncrypt initialized. Account key (%s) exists. CA %s" % (self.account_key, self.ca))
            return

        code, result = self.register()
        if code != 201:
            self.log("Failed to register new LetsEncrypt account. Reply: %s" % str(result))
            raise RuntimeError("Failed to register LetsEncrypt account")

    def issue_certificate(self, hostname, force=False):
        if not force and self._storage.exists(self.get_fullchain_url(hostname)):
            self.log("Certificate for %s already available" % hostname)
            return True

        cert = self.sign(hostname, self.get_csr(hostname))

        self._storage.write(self.get_crt_url(hostname), cert)
        self.log("Generated certificate for %s, saved to %s" % (hostname, self.get_crt_url(hostname)))

        self.get_full_chain(hostname, force_reload=True)

    def get_account_key(self):
        """
        Generate account key

        :return:
        """
        if os.path.exists(self.account_key):
            return self.account_key

        generate_cmd = ['openssl', 'genrsa', '-out', self.account_key, str(self.account_key_size)]
        cmd = subprocess.Popen(generate_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = cmd.wait()
        self.log("Generating key size %d, path: %s" % (self.account_key_size, self.account_key))
        if res != 0:
            raise RuntimeError("Failed to generate account key, path: %s" % self.account_key)

        return self.account_key

    def _b64(self, b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    def _jwk(self):
        proc = subprocess.Popen(["openssl", "rsa", "-in", self.get_account_key(), "-noout", "-text"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))

        pub_hex, pub_exp = re.search(r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        return {
            "alg": "RS256",
            "jwk": {
                "e": self._b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": self._b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
            },
        }

    def _request(self, url, payload):
        self.log("Generating new request to %s" % url)

        header = self._jwk()

        payload64 = self._b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(self.ca + "/directory", timeout=10).headers['Replay-Nonce']

        protected64 = self._b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", self.get_account_key()], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": self._b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except (IOError, OSError) as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    def register(self):
        """
        Register new ACME account

        :return:
        """
        code, result = self._request(self.ca + "/acme/new-reg", {
            "resource": "new-reg",
            "agreement": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf"
        })
        return code, result

    def challenge(self, uri, key_authorization):
        code, result = self._request(uri, {
            "resource": "challenge",
            "keyAuthorization": key_authorization,
        })
        return code, result

    def new_cert(self, csr):
        code, result = self._request(self.ca + "/acme/new-cert", {
            "resource": "new-cert",
            "csr": csr,
        })
        return code, result

    def sign(self, hostname, csr):
        """
        Sign new certificate

        :param hostname:
        :param csr:
        :return:
        """

        # lets check if this is a new issue or we are already have active certificate for this domain
        if not self.certificate_exists(hostname) and self._rate_limit_last > time.time() - 43200:
            mins_ago = int((time.time() - self._rate_limit_last)/60)
            raise RuntimeError("Denied sign because we have reached cert limit. Last error was %d mins ago" % mins_ago)

        self.log("Signing new CSR, hostname %s" % hostname)
        code, result = self._request(self.ca + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": hostname},
        })

        if code != 201:
            self.log("Failed to start new issue. Got reply code: %d, answer: %s" % (code, result))
            raise RuntimeError("Failed to run auth. Reply code: %d" % code)

        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == self._hook.get_challenge_type()][0]

        accountkey_json = json.dumps(self._jwk()['jwk'], sort_keys=True, separators=(',', ':'))
        thumbprint = self._b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        key_authorization = "{0}.{1}".format(token, thumbprint)

        challenge_token = self._b64(hashlib.sha256(key_authorization.encode('utf8')).digest())
        self._hook.deploy_challenge(hostname, challenge_token, key_authorization)
        self.challenge(challenge['uri'], key_authorization)

        try_until = time.time() + self._challenge_timeout
        completed = False
        self.log("Waiting for challenge verification for %s" % hostname)
        while time.time() < try_until:
            try:
                resp = urlopen(challenge['uri'], timeout=10).read()
                res = json.loads(resp)
            except IOError as e:
                self.log("IOError, failed to get response from challenge verification script. " % e.message)
                time.sleep(self._challenge_sleep)
                continue

            if res['status'] != 'valid':
                self.log("Challenge verification is not completed. Current status: %s" % res['status'])
                time.sleep(self._challenge_sleep)

            self.log("Challenge for %s completed" % hostname)
            completed = True
            break

        if not completed:
            self.log("Failed to complete challenge in acceptable time. Timeout (%d) expired" % self._challenge_timeout)
            self._hook.clean_challenge(hostname, challenge_token)
            return False

        # get the new certificate
        self.log("Signing certificate for %s" % hostname)

        csr_temp_file = self.get_temp_path()
        with open(csr_temp_file, 'w') as csr_file:
            csr_file.write(csr)

        proc = subprocess.Popen(["openssl", "req", "-in", csr_temp_file, "-outform", "DER"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        csr_der, err = proc.communicate()
        code, result = self.new_cert(self._b64(csr_der))

        self._hook.clean_challenge(hostname, challenge_token)

        if code == 429:
            info = json.loads(result)
            if 'type' in info:
                if info['type'] == 'urn:acme:error:rateLimited':
                    self._rate_limit_last = time.time()
                    raise RuntimeError("Rate limit reached")

        if code != 201:
            raise RuntimeError("Error signing certificate: {0} {1}".format(code, result))

        return self.convert2pem(result)