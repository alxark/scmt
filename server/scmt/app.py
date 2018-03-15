from config import ConfigReader
from manager import Manager
import api
import storages.builder
import loggable


class App(loggable.Loggable):
    _instance = False

    def __init__(self):
        self.config = False

    def set_config(self, config):
        self.config = ConfigReader(config)

    def start(self):
        self.log("Starting app. Initializing storage")

        storage_configs = self.config.get_storages()
        storage_list = {}
        for storage_name in storage_configs:
            storage = storage_configs[storage_name]
            storage_list[storage_name] = storages.builder.build(storage)

        manager = Manager(self.config.dir, self.config.get_domains(), storage_list)

        api_service = api.service.Service(manager, self.config.port, self.config.ssl)
        api_service.start()

        manager.start()


    @staticmethod
    def i():
        if not App._instance:
            App._instance = App()
        return App._instance


