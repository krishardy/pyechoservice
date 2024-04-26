import socketserver
import sys
import argparse
import logging
import time
import threading
import enum
import http
import ssl
import http.server

import yaml

logger = logging.getLogger(__name__)

threads: list[threading.Thread] = []

def main():
    parser = argparse.ArgumentParser(description="Listen on a port and echo a response")
    parser.add_argument("-c", "--config", type=str, default="/etc/pyecho.yml", help="Configuration file (Default=%(default)s)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    logger.debug(args)

    config = {}
    with open(args.config, "r") as fh:
        config = yaml.safe_load(fh)
    logger.debug(config)

    ports = []
    expand_ports([config['ports']], ports)

    if config['tcp'] is True:
        bind_tcp(config['ip'], ports, config['certfile'])
    if config['udp'] is True:
        bind_udp(config['ip'], ports)

    if len(threads) > 0:
        try:
            while True:
                time.sleep(60)
        except Exception:
            pass

    for t in threads:
        t.close()
    for t in threads:
        t.join()

def expand_ports(ports, output):
    for p in ports:
        if p == "*":
            output.extend(list(range(1, 65535)))
        elif ',' in p:
            expand_ports(p.split(','), output)
        elif '-' in p:
            limits = p.split('-')
            output.extend(list(range(int(limits[0]), int(limits[1])+1)))
        else:
            output.append(int(p))

class Proto(enum.IntEnum):
    TCP = 0
    UDP = 1

class EchoService(threading.Thread):
    def __init__(self, proto: Proto, ip: str, port: int, certfile: str=None):
        logger.debug(f"EchoService.__init__({proto}, {ip}, {port})")
        self.proto = proto
        self.ip = ip
        self.port = port
        self.certfile = certfile
        self.server = None
        self.start()
    
    def start(self):
        logger.debug("EchoService.start()")
        if self.proto == Proto.TCP:
            if self.port == 80:
                self.server = http.server.HTTPServer((self.ip, self.port), HttpEchoHandlerClassFactory.create(self.proto, self.ip, self.port))
            elif self.port == 443:
                self.server = http.server.HTTPServer((self.ip, self.port), HttpEchoHandlerClassFactory.create(self.proto, self.ip, self.port))
                if self.certfile:
                    self.server.socket = ssl.wrap_socket(self.server.socket, server_side=True, certfile=self.certfile, ssl_version=ssl.PROTOCOL_TLSv1_2)
            else:
                self.server = socketserver.TCPServer((self.ip, self.port), EchoHandlerClassFactory.create(self.proto, self.ip, self.port))
        elif self.proto == Proto.UDP:
            self.server = socketserver.UDPServer((self.ip, self.port), EchoHandlerClassFactory.create(self.proto, self.ip, self.port))

        if self.server is not None:
            self.server.timeout = 2
            try:
                while True:
                    self.server.handle_request()
            finally:
                self.server.server_close()

class EchoHandlerClassFactory:
    @staticmethod
    def create(proto, ip, port, timeout=2):
        class EchoHandler(socketserver.BaseRequestHandler):
            def handle(self):
                logger.debug("EchoHandler.handle()")
                self.request.settimeout(timeout)
                data = self.request.recv(1024).strip()
                output = bytearray(self.client_address[0].encode('utf-8'))
                output.extend(b':')
                output.extend(str(self.client_address[1]).encode('utf-8'))
                output.extend(b' ')
                output.extend(data)
                logmessage = bytearray(str(f"{proto}:{ip}:{port}").encode('utf-8'))
                logmessage.extend(b' ')
                logmessage.extend(output)
                logger.debug(logmessage)
                self.request.sendall(output)
            
        return EchoHandler

class HttpEchoHandlerClassFactory:
    @staticmethod
    def create(proto, ip, port, timeout=2):
        class HttpEchoHandler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.request.settimeout(timeout)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

            def do_GET(self):
                self.request.settimeout(timeout)
                requestline = self.requestline.encode('utf-8')
                headers = bytes(self.headers)
                data_length = self.headers.get('Content-Length')
                data = b''
                if data_length is not None:
                    data = self.rfile.read(data_length).strip()

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                output = bytearray(self.client_address[0].encode('utf-8'))
                output.extend(b':')
                output.extend(str(self.client_address[1]).encode('utf-8'))
                output.extend(b'\n')
                output.extend(requestline)
                output.extend(b'\n')
                output.extend(headers)
                output.extend(b'\n')
                output.extend(data)
                logmessage = bytearray(str(f"{proto}:{ip}:{port}").encode('utf-8'))
                logmessage.extend(b' ')
                logmessage.extend(output)
                logger.debug(logmessage)
                self.wfile.write(b"<html><head><title>ECHO</title></head>")
                self.wfile.write(b"<body>\n<pre>\n")
                self.wfile.write(output)
                self.wfile.write(b"</pre></body></html>")

        return HttpEchoHandler

def bind_tcp(ip, ports, certfile=None):
    for p in ports:
        t = threading.Thread(target=EchoService, args=(Proto.TCP, "" if ip == "*" else ip, p, certfile))
        t.name = f"{ip}:{p}"
        t.start()
        threads.append(t)

def bind_udp(ip, ports):
    for p in ports:
        t = threading.Thread(target=EchoService, args=(Proto.UDP, "" if ip == "*" else ip, p))
        t.name = f"{ip}:{p}"
        t.start()
        threads.append(t)

if __name__ == "__main__":
    sys.exit(main())
