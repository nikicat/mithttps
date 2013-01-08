import socket
import logging
from contextlib import closing

from http_parser.http import HttpStream
from http_parser.reader import SocketReader

import deferred
import exlogging

@exlogging.wrap
class Proxy:
    def __init__(self, host, port):
        self.socks = []
        for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP):
            sock = socket.socket(family, socktype, proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
            sock.bind(sockaddr[:2])
            sock.listen(100)
            self.socks.append(sock)

    def run(self):
        for sock in self.socks:
            self.accept(sock)
        self.accept.worker.join()

    @deferred.thread
    def accept(self, listener):
        while True:
            sock, peer = listener.accept()
            self.handle(sock, peer)

    @deferred.thread
    @exlogging.wrap
    def handle(self, upsock, peer):
        with closing(upsock) as upsock:
            origaddr = upsock.getsockname()
            self.logger.debug('intercepted connection from {0} to {1}'.format(peer, origaddr))
            p = HttpStream(SocketReader(upsock))
            self.logger.debug('request: method={0} url={1} version={2} headers={3}'.format(p.method(), p.url(), p.version(), p.headers()))
            family, socktype, proto, canonname, sockaddr = socket.getaddrinfo(origaddr[0], origaddr[1], 0, socket.SOCK_STREAM)[0]
            with closing(socket.socket(family, socktype, proto)) as downsock:
                #downsock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
                #downsock.bind(peer[:2])
                downsock.connect(origaddr[:2])
                downsock.send('{method} {url} HTTP/{version[0]}.{version[1]}\r\n{headers}\r\n\r\n'.format(method=p.method().decode(), url=p.url(), version=p.version(), headers='\r\n'.join(['{0}: {1}'.format(name, value) for name, value in p.headers().items()])).encode())
                downstream = HttpStream(SocketReader(downsock))
                self.logger.debug('response: header={0}'.format(downstream.headers()))
                upsock.send('HTTP/{version[0]}/{version[1]} {code} {status}\r\n{headers}\r\n\r\n'.format(version=downstream.version(), code=downstream.status_code(), status=downstream.status(), headers='\r\n'.join(['{0}: {1}'.format(name, value) for name, value in downstream.headers().items()])).encode())
                upsock.send(downstream.body_string())

if __name__ == '__main__':
    logging.basicConfig(level=logging.TRACE)
    p = Proxy('0.0.0.0', 3128)
    p.run()
