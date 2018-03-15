import requests
import json
import base64
import threading
import time


class Consul:
    """
    Consul backend for storing credentials
    """
    def __init__(self, consul_addr='172.17.0.1:8500', logger=None):
        self.consul_addr = consul_addr.replace('http://', '').replace('/','')
        self.cache_time = 10
        self.logger = logger
        self._cache = {}
        self._cacheLock = threading.Lock()

    def log(self, msg):
        if self.logger:
            self.logger.log('[CONSUL] ' + msg)

    def exists(self, path):
        try:
            self.read(path)
            return True
        except IndexError:
            try:
                self.list(path)
                return True
            except IndexError:
                return False

    def list(self, path):
        """
        Read list of keys or subdirectories for specific path

        :param path:
        :return:
        """
        url = 'http://%s/v1/kv/%s?keys' % (self.consul_addr, path)
        self.log('[CONSUL] GET KEYS %s' % url)

        response = requests.get(url, timeout=10)

        if len(response.text) == 0:
            raise IndexError("No such directory %s" % path)

        decoded = json.loads(response.text)
        sub_dirs = []
        if path[-1] != '/':
            path += '/'

        for subdir in decoded:
            dir_name = str(subdir.replace(path, '', 1).split('/')[0])
            if len(dir_name) == 0:
                continue

            if dir_name not in sub_dirs:
                sub_dirs.append(dir_name)

        return sub_dirs

    def read(self, key):
        """
        Read key information

        :param key:
        :return:
        """
        if key in self._cache and self._cache[key]['expire'] < time.time():
            return self._cache[key]['value']

        url = 'http://%s/v1/kv/%s' % (self.consul_addr, key)
        self.log("[CONSUL] GET %s" % url)
        response = requests.get(url, timeout=10)

        if len(response.text) == 0:
            raise IndexError("No key text found! Key: %s" % url)

        decoded = json.loads(response.text)
        if len(decoded) != 1 or not decoded[0]['Value']:
            raise IndexError("Incorrect data in Value object")

        value = base64.decodestring(decoded[0]['Value'])
        with self._cacheLock:
            self._cache[key] = {'expire': time.time() + self.cache_time, 'value': value}
            self._clean_cache()

        return value

    def write(self, key, value):
        if key[0] != '/':
            key = '/%s' % key

        url = 'http://%s/v1/kv%s' % (self.consul_addr, key)
        self.log("PUT %s" % url)
        response = requests.put(url, data=str(value))

        self.log("RESPONSE: %s" % str(response.text))
        with self._cacheLock:
            self._cache[key] = {'expire' : time.time() + self.cache_time, 'value': value}

        return True

    def _clean_cache(self):
        """
        Remove items from cache

        :return:
        """
        for key in self._cache.keys():
            if self._cache[key]['expire'] < time.time():
                continue

            del(self._cache[key])

    def delete(self, key):
        if key[0] != '/':
            key = '/%s' % key

        url = 'http://%s/v1/kv%s?recurse=true' % (self.consul_addr, key)
        self.log("DELETE %s" % url)
        response = requests.delete(url, timeout=10)
        self.log("[RESPONSE]: %s" % str(response.text))

        return True





