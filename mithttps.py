import socket
import logging
from contextlib import closing, contextmanager
import urllib.parse
import threading

from http_parser.http import HttpStream
from http_parser.reader import SocketReader

import deferred
import exlogging

@exlogging.wrap
class Proxy:
    def __init__(self, host, port, transparent=False):
        self.socks = []
        for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP):
            sock = socket.socket(family, socktype, proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if transparent:
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
            url = None
            if p.method() == b'CONNECT':
                self.handle_connect(p, upsock)
            elif p.url()[0] == '/':
                self.handle_transparent(p, upsock)
            else:
                self.handle_proxy(p, upsock)

    @contextmanager
    def connect_downstream(self, rhost, rport):
        for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(rhost, rport, 0, socket.SOCK_STREAM):
            self.logger.debug('trying to connect to {0}'.format(sockaddr))
            with closing(socket.socket(family, socktype, proto)) as downsock:
                #downsock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
                #downsock.bind(peer[:2])
                downsock.connect(sockaddr)
                self.logger.debug('connected to {0}'.format(sockaddr))
                yield downsock
                break

    def send_downstream(self, p, rhost, rport, method, url, upsock):
        with self.connect_downstream(rhost, rport) as downsock:
            request = '{method} {url} HTTP/{version[0]}.{version[1]}\r\n{headers}\r\n\r\n'.format(method=method.decode(), url=url, version=p.version(), headers='\r\n'.join(['{0}: {1}'.format(name, value) for name, value in p.headers().items()]))
            self.logger.debug('sending request {0!r}'.format(request))
            downsock.send(request.encode())
            downstream = HttpStream(SocketReader(downsock))
            self.logger.debug('response: header={0}'.format(downstream.headers()))
            upsock.send('HTTP/{version[0]}.{version[1]} {code} {status}\r\n{headers}\r\n\r\n'.format(version=downstream.version(), code=downstream.status_code(), status=downstream.status(), headers='\r\n'.join(['{0}: {1}'.format(name, value) for name, value in downstream.headers().items()])).encode())
            upsock.send(downstream.body_string())

    def handle_proxy(self, p, upsock):
        url = urllib.parse.urlparse(p.url())
        self.send_downstream(p, url.hostname, url.port or 80, p.method(), url.path or '/', upsock)

    def handle_transparent(self, p, upsock):
        rhost,rport = origaddr[:2]
        self.send_downstream(p, rhost, rport, p.method(), p.url(), upsock)

    def handle_connect(self, p, upsock):
        rhost,rport = p.url().split(':')
        with self.connect_downstream(rhost, rport) as downsock:
            upsock.send(b'HTTP/1.1 200 OK\r\n\r\n')
            downcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            with closing(downcontext.wrap_socket(downsock, do_handshake_on_connect=False, server_hostname=rhost)) as ssldownsock:
                ssldownsock.do_handshake()
                downcert = ssldownsock.getpeercert()
                upcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                with closing(upcontext.wrap_socket(upsock, do_handshake_on_connect=False)) as sslupsock:
                    upcert = self.generate_cert(downcert)
                    downcontext.load_cert_chain()
                def pump(src, dst):
                    while True:
                        data = src.recv(1024)
                        if data is None:
                            dst.close()
                            break
                        dst.send(data)
                pumps = [threading.Thread(target=pump, args=(upsock, downsock)), threading.Thread(target=pump, args=(downsock, upsock))]
                self.logger.debug('start pumping between sockets')
                for p in pumps:
                    p.start()
                for p in pumps:
                    p.join()

if __name__ == '__main__':
    stderr = logging.StreamHandler()
    stderr.setLevel(logging.DEBUG)
    stderr.setFormatter(logging.Formatter('{asctime} {name} {levelname} {message}', style='{'))

    trace = logging.StreamHandler()
    trace.addFilter(exlogging.HasAttrFilter('params'))
    trace.setFormatter(logging.Formatter('{asctime} {name} {levelname} {message} {params}', style='{'))

    logging.getLogger().addHandler(stderr)
    logging.getLogger().addHandler(trace)
    logging.getLogger().setLevel(logging.TRACE)
    logging.getLogger('appname.deferred').setLevel(logging.INFO)

    p = Proxy('0.0.0.0', 3128)
    p.run()
