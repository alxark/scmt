import unittest
import consul
import os
import random


class ConsulTestCase(unittest.TestCase):
    def setUp(self):
        self.consul_address = os.getenv('CONSUL_HTTP_ADDR')
        if not self.consul_address:
            self.assertTrue(self.consul_address, "No CONSUL_HTTP_ADDR provided. Failed to continue")

    def test_write_read_ops(self):
        kv = consul.Consul(self.consul_address)

        key_name = 'tests/key%s' % str(random.random())
        key_data = str(random.random())
        kv.write(key_name, key_data)

        storage_data = kv.read(key_name)
        self.assertEqual(storage_data, key_data)

    def test_negative_cases(self):
        kv = consul.Consul(self.consul_address)
        key_name = 'tests/key%s' % str(random.random())

        try:
            storage = kv.read(key_name)
            self.assertFalse(storage, "Some data returned for wrong key!")
        except IndexError:
            pass

    def test_listing_and_removal(self):
        kv = consul.Consul(self.consul_address)

        rand = str(random.random())
        files = [
            "r%s/b%s/c%s" % (rand, rand, rand),
            "r%s/d%s/e%s" % (rand, rand, rand),
            "r%s/f%s/g%s" % (rand, rand, rand),
        ]

        for file_name in files:
            kv.write(file_name, rand)

        dirs = kv.list('r%s/' % rand)
        self.assertEqual(3, len(dirs))
        self.assertTrue('b%s' % rand in dirs)
        self.assertTrue('d%s' % rand in dirs)
        self.assertTrue('f%s' % rand in dirs)

        kv.delete('r%s' % rand)

        dirs = kv.list('r%s' % rand)
        self.assertEqual(len(dirs), 0)

