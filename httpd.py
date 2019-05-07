
import socket
import argparse
import logging as log


class Server:
    def __init__(self, host, port, doc_path, queue=5):
        self.host = host
        self.port = port
        self.root = doc_path
        self.queue = queue

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
            log.debug('Server socket has been closed!')
        else:
            self.server_socket.listen(self.queue)
            log.debug(f'Server has been started on <{self.host}: {self.port}>.')




def parse_args():
    parser = argparse.ArgumentParser(description='Simple synchronous http server. GET, HEAD methods only.')

    parser.add_argument('-m', '--master', type=str, default='localhost', help='Hostname, default - localhost.')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Port, default - 8000.')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Server workers, default - 4.')
    parser.add_argument('-r', '--root', type=str, default='doc_path', help='DOCUMENT_ROOT directory.')
    parser.add_argument('-l', '--level', type=str, default='DEBUG', help='Logging level, default - DEBUG')

    return parser.parse_args()


def set_logging(level):
    log.basicConfig(
        level=level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S',
    )



if __name__ == '__main__':

    args = parse_args()
    set_logging(args.level)

    server = Server(args.master, args.port, args.root)
    server.run()
