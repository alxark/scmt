# coding: utf-8
import time
import threading
import sys


class Loggable:
    def log(self, msg, level='info'):
        thread_name = threading.currentThread().name

        sys.stdout.write(time.strftime('%Y/%m/%d %R ', time.localtime()) + '[' + thread_name + '] [' + level + '] ' + msg.strip() + "\n")
        sys.stdout.flush()