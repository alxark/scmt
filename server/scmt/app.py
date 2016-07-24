from config import ConfigReader
from manager import Manager
from api import Api

import loggable


class App(loggable.Loggable):
    _instance = False

    def __init__(self):
        self.config = False

    def set_config(self, config):
        self.config = ConfigReader(config)

    def start(self):
        self.log("Starting app")
        manager = Manager(self.config.dir, self.config.get_domains())
        api = Api(manager, self.config.port, self.config.ssl)
        api.start()
        manager.start()


    @staticmethod
    def i():
        if not App._instance:
            App._instance = App()
        return App._instance


