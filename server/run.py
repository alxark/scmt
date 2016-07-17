import scmt
from scmt.app import App
App.i().set_config('/var/www/scmt/examples/config.ini')
App.i().start()