import loggable
import ConfigParser


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

        self.dir = parser.get('general', 'dir')
        self.log("Application working dir %s" % self.dir)

        self.port = parser.getint('general', 'port')
        self.log("Listen port %d" % self.port)

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

