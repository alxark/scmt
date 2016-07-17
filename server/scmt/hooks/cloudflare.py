import dns.exception
import dns.resolver
import requests
import sys
import time
from tld import get_tld
import scmt.loggable


class Cloudflare(scmt.loggable.Loggable):
    def __init__(self, options):
        if 'email' not in options:
            raise RuntimeError("CloudFlare Hook Error. No Email provided.")
        self._email = options['email']

        if 'key' not in options:
            raise RuntimeError("CloudFlare Hook Error. No Key in options.")
        self._key = options['key']

        if 'dns' not in options:
            self._dns = ['8.8.8.8']
        else:
            self._dns = options['dns'].split(',')

        self.log("CloudFlare hook initialized, Email: %s" % self._email)
        self._timeout = 1800

    def get_headers(self):
        return {
            'X-Auth-Email': self._email,
            'X-Auth-Key': self._key,
            'Content-Type': 'application/json',
        }

    def _propagated(self, name, token):
        txt_records = []
        try:
            if self._dns:
                custom_resolver = dns.resolver.Resolver()
                custom_resolver.nameservers = self._dns
                dns_response = custom_resolver.query(name, 'TXT')
            else:
                dns_response = dns.resolver.query(name, 'TXT')

            for rdata in dns_response:
                for txt_record in rdata.strings:
                    txt_records.append(txt_record)
        except dns.exception.DNSException:
            return False

        for txt_record in txt_records:
            if txt_record == token:
                return True

        return False

    def _get_zone_id(self, domain):

        tld = get_tld('http://' + domain)

        url = "https://api.cloudflare.com/client/v4/zones?name={0}".format(tld)
        r = requests.get(url, headers=self.get_headers())
        r.raise_for_status()
        return r.json()['result'][0]['id']

    def _get_txt_record_id(self, zone_id, name, token):
        url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records?type=TXT&name={1}&content={2}".format(zone_id, name, token)
        r = requests.get(url, headers=self.get_headers())
        r.raise_for_status()
        try:
            record_id = r.json()['result'][0]['id']
        except IndexError:
            self.log("Unable to locate record named {0}".format(name))
            return

        return record_id

    def deploy_challenge(self, domain, token):
        self.log("Creating new TXT record %s, token %s" % (domain, token))
        zone_id = self._get_zone_id(domain)
        name = "{0}.{1}".format('_acme-challenge', domain)
        url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
        payload = {
            'type': 'TXT',
            'name': name,
            'content': token,
            'ttl': 1,
        }

        r = requests.post(url, headers=self.get_headers(), json=payload)
        r.raise_for_status()
        record_id = r.json()['result']['id']

        self.log("Created new TXT record: %s" % record_id)
        time.sleep(10)

        end_time = time.time() + self._timeout
        started = time.time()
        while time.time() < end_time:
            if self._propagated(name, token):
                self.log("Domain %s propagated successfully" % domain)
                break

            self.log("DNS not propagated, waiting 30s, total time: %d..." % (time.time() - started))
            time.sleep(30)

    def clean_challenge(self, domain, token):
        zone_id = self._get_zone_id(domain)
        name = "{0}.{1}".format('_acme-challenge', domain)
        record_id = self._get_txt_record_id(zone_id, name, token)

        self.log("Deleting TXT record name: %s" % name)
        url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
        r = requests.delete(url, headers=self.get_headers())
        r.raise_for_status()