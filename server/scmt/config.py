import loggable
import ConfigParser
from ConfigParser import NoOptionError

class ConfigReader(loggable.Loggable):
    _dir = False
    # port to listen for HTTP API
    port = 8790
    # storage for domains
    _domains = {}

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

        self.ssl = parser.get('general', 'ssl')
        self.log("Using SSL certificate for local connections, hostname: %s" % self.ssl)

        sections = parser.sections()
        sections.remove('general')

        for domain in sections:
            self.log("Parsing section %s" % domain)
            options = parser.options(domain)

            self._domains[domain] = {}
            for opt in options:
                self._domains[domain][opt] = parser.get(domain, opt)

    def get_domains(self):
        return self._domains

