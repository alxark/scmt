# coding: utf-8
import time
import threading


class Loggable:
    def log(self, msg, level='info'):
        thname = threading.currentThread().name
        print(time.strftime('%Y/%m/%d %R ', time.localtime()) + '[' + thname + '] [' + level + '] ' + msg.strip())