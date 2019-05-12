import sys
import socket
import multiprocessing
import threading
import argparse
import logging as log


class Request:
    def __init__(self, request):
        self.request = request
        self.methods = ['GET', 'HEAD']


    def evaluate_request(self):
        # log.debug('request: ', self.request)
        try:
            query_string = self.request.split(maxsplit=2)[1]
        except Exception as ex:
            log.error(ex)
            return 400

        # method, urn = self.request.split(maxsplit=2)[:2]
        # log.debug(f'method: {method}, urn: {urn}')

        log.debug(query_string)

        # if method not in self.methods:
        #     return 405, method, urn
        #








class Server:
    def __init__(self, host, port, rootdir):
        self.host = host
        self.port = port
        self.root = rootdir

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    def run(self):
        try:
            self.server_socket.bind((self.host, self.port))
        except Exception as ex:
            log.error(ex)
            log.debug(f'Server socket has not been bound at <{self.host}: {self.port}>!')
            self.server_socket.close()
            # sys.exit(1)
        else:
            self.server_socket.listen(5)
            log.debug(f'Server has been started on <{self.host}: {self.port}>.')

            return self.accept_client()


    def accept_client(self):
        # while True:
        log.debug('Waiting for client.')
        client_socket, client_addr = self.server_socket.accept()
        log.debug(f'New connection: {client_socket}')
        # try:
        #     clients_handler = threading.Thread(target=self.client_handler, args=(client_socket, client_addr))
        # except Exception as ex:
        #     log.error(ex)
        #     client_socket.close()
        # else:
        #     log.debug(f'New process for {client_addr[1]} has been started')
        #     clients_handler.start()

        return self.clients_handler(client_socket, client_addr)


    def clients_handler(self, client_socket, client_addr):

        log.debug("Waiting for client's message:")
        client_query = self.get_request(client_socket)
        log.debug(f'Message from {client_addr[1]}:\n{client_query}')

        # client_socket.send('Server got it!\n'.encode(encoding='utf-8'))
        # client_socket.close()
        request = Request(client_query)
        request.evaluate_request()
        client_socket.close()
        log.debug(f'Client socket {client_addr[1]} has been closed')
        log.debug('************************************************')
        return client_query


    def get_request(self, client_socket):
        buff = 1024
        data = b''
        while True:
            chunk = client_socket.recv(buff)
            data += chunk
            if len(chunk) < buff:
                break
        return data.decode(encoding='utf-8')



def parse_args():
    parser = argparse.ArgumentParser(description='Simple synchronous http server. GET, HEAD methods only.')

    parser.add_argument('-m', '--master', type=str, default='localhost', help='Hostname, default - localhost.')
    parser.add_argument('-p', '--port', type=int, default=8888, help='Port, default - 8888.')
    parser.add_argument('-w', '--workers', type=int, default=1, help='Server workers, default - 1.')
    parser.add_argument('-r', '--root', type=str, default='rootdir', help='DOCUMENT_ROOT directory.')
    parser.add_argument('-l', '--level', type=str, default='DEBUG', help='Logging level, default - DEBUG.')

    return parser.parse_args()


def set_logging(level):
    log.basicConfig(
        level=level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S',
    )


def start_server(*args):
    try:
        server = Server(*args)
        server.run()
    except KeyboardInterrupt:
        log.debug('Server has been interrupted.')


if __name__ == '__main__':

    args = parse_args()
    set_logging(args.level)

    for _ in range(args.workers):
        start_server(args.master, args.port, args.root)
