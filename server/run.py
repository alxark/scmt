#!/usr/bin/python
import sys
import os
from scmt.app import App

if len(sys.argv) != 2:
    if os.path.exists('/etc/scmt.ini'):
        config = '/etc/scmt.ini'
    else:
        print("Running scmt.py <CONFIG>")
        sys.exit(1)
else:
    config = sys.argv[1]

App.i().set_config(config)
App.i().start()
