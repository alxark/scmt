import sys
from scmt.app import App

if len(sys.argv) != 2:
    print("Running scmt.py <CONFIG>")
    sys.exit(1)

App.i().set_config(sys.argv[1])
App.i().start()