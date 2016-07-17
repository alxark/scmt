# coding: utf-8
import time


class Loggable:
    def log(self, msg):
        print(time.strftime('%Y/%m/%d %R ', time.localtime()) + msg.strip())