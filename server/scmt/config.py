import loggable
import ConfigParser
from ConfigParser import NoOptionError


class ConfigReader(loggable.Loggable):
    _dir = False
    # port to listen for HTTP API
    port = 8790
    # storage for domains
    _domains = {}
    _storages = {}

    def __init__(self, path):
        parser = ConfigParser.ConfigParser()
        self.log("Loading configuration from %s" % path)
        parser.read(path)

        try:
            self.dir = parser.get('general', 'dir')
            self.log("Application working dir %s" % self.dir)
        except NoOptionError:
            self.dir = '/var/lib/scmt'
            self.log("Using default data dir: /var/lib/scmt")

        try:
            self.port = parser.getint('general', 'port')
            self.log("Listen port %d" % self.port)
        except NoOptionError:
            self.port = 443
            self.log("Using default port 443")

        try:
            self.ssl = parser.get('general', 'ssl')
            self.log("Using SSL certificate for local connections, hostname: %s" % self.ssl)
        except NoOptionError:
            self.ssl = False
            self.log("SSL support disabled")

        sections = parser.sections()
        sections.remove('general')

        for section in sections:
            options = parser.options(section)
            values = {}
            for option in options:
                values[option] = parser.get(section, option)

            if 'type' in values and values['type'] == 'storage':
                self._storages[section] = self.parse_storage_values(values)
            else:
                self._domains[section] = self.parse_domain_values(values)

    def parse_storage_values(self, values):
        return values

    def parse_domain_values(self, values):
        return values

    def get_storages(self):
        return self._storages

    def get_domains(self):
        return self._domains

