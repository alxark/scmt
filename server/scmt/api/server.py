import BaseHTTPServer
import socket
import sys
from SocketServer import ThreadingMixIn


class Server(ThreadingMixIn, BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, request_handler_class, bind_and_activate=True, manager=False):
        self.manager = manager
        BaseHTTPServer.HTTPServer.__init__(self, server_address, request_handler_class, bind_and_activate)

    def finish(self, *args, **kw):
        try:
            if not self.wfile.closed:
                self.wfile.flush()
                self.wfile.close()
        except socket.error:
            self.log("""Exception: %s""" % sys.exc_info()[1])
            pass

        self.rfile.close()