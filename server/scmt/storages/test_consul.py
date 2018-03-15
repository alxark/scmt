import unittest
import storages.consul

class ConsulTestCase(unittest.TestCase):
    def test_storage_creation(self):
        consul = Consul()

