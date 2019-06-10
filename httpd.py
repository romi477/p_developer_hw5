import os
import re
import socket
import argparse
import mimetypes
import logging as log
import multiprocessing
from datetime import datetime
from urllib.parse import unquote
from multiprocessing.dummy import Pool


ERRORS = {
    400: 'BAD_REQUEST',
    403: 'FORBIDDEN',
    404: 'NOT_FOUND',
    405: 'METHOD_NOT_ALLOWED',
}


class Response:
    def __init__(self, query, root):
        self.query = query
        self.root = root
        self.methods = ['GET', 'HEAD']
        self.exts = ['', 'txt', 'html', 'css', 'js', 'jpg', 'png', 'jpeg', 'gif', 'swf']

    def execute(self):
        request_params = self.evaluate_request()
        log.debug(f'Request params: {request_params}')
        data = self.generate_response(*request_params)
        return data

    def evaluate_request(self):
        method = urn = message = ''
        if self.query:
            method = self.query['method']
            code, urn, message = self.get_response_data()
        else:
            code = 400
            log.debug('Bad request!')
        return code, method, urn, message

    def get_response_data(self):
        items = '; '.join([f'{k}: {v}' for k, v in self.query.items()])
        if self.query['addition'] and not self.query['addition'].startswith('?'):
            return 400, items, f'at least query argument "{self.query["addition"]}" have some mistakes'

        local_path = os.path.join(self.root + self.query['dir'] + (self.query['file'] or 'index.html'))
        local_path = os.path.normpath(local_path)
        
        if self.root not in local_path.split(os.path.sep):
            return 403, local_path, '"../" document root escaping forbidden'

        global_path = os.path.join(os.path.abspath('.'), local_path)

        if self.query['method'] not in self.methods:
            return 405, global_path, f'method {self.query["method"]} not allowed'

        ext = self.query['file'].split('.')[-1].lower()
        
        if ext not in self.exts:
            return 403, global_path, f'"*.{ext}" files not allowed for displaying'

        if '.' in self.query['dir']:
            return 404, global_path, f'invalid directory name "{self.query["dir"]}", dots in the directory path are not allowed'

        if not os.path.exists(global_path):
            return 404, global_path, 'make sure exactly that file is required'

        return 200, global_path, 'everything is ok'

    def generate_response(self, code, method, urn, message):
        headers = self.get_headers(code, urn)
        
        if code == 200:
            if method == 'GET':
                with open(urn, 'rb') as body:
                    return b'\r\n\r\n'.join([headers, body.read()])
            return headers + b'\r\n\r\n'
        return b'\r\n\r\n'.join([headers, f'{code} {ERRORS.get(code, "INTERNAL_ERROR")}:\n\n{urn}\n\nHINT: {message}'.encode('utf-8')])

    @staticmethod
    def get_headers(code, urn):
        cont_len = os.path.getsize(urn) if os.path.exists(urn) else ''
        cont_type = mimetypes.guess_type(urn)[0] if os.path.exists(urn) else ''

        items = [
            f'HTTP/1.1 {code} {ERRORS.get(code, "INTERNAL_ERROR")}',
            f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            'Server: Simple HTTP server',
            f'Content-Length: {cont_len}',
            f'Content-Type: {cont_type}',
            'Connection: close'
        ]
        return ('\r\n'.join(items)).encode('utf-8')


class Server:
    
    def __init__(self, host, port, rootdir):
        self.host = host
        self.port = port
        self.rootdir = rootdir

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    def run(self):
        try:
            self.server_socket.bind((self.host, self.port))
        except Exception as ex:
            log.debug(ex)
            log.error(f'Server socket has not been bound at <{self.host}: {self.port}>!')
            self.server_socket.close()
        else:
            self.server_socket.listen(5)
            log.info(f'Server has been started on <{self.host}: {self.port}>.')
            self.serve_forever()

    def serve_forever(self):
        pool = Pool()

        while True:
            log.debug('Waiting for client...')
            client = self.server_socket.accept()
            log.debug(f'New connection: {client[0]}')
            pool.map(self.clients_handler, [client])

    def clients_handler(self, args):
        client_socket, client_addr = args
        log.debug("Waiting for client's message...")
        client_query = self.get_client_data(client_socket)
        log.debug(f'Message from {client_addr[1]}: {client_query}')

        query_dict = self.parse_request(client_query)
        log.debug(f'Parsed params: {query_dict.items()}')

        response = Response(query_dict, self.rootdir)
        data = response.execute()
        client_socket.sendall(data)
        client_socket.close()
        log.debug(f'Client socket {client_addr[1]} has been closed')

    @staticmethod
    def get_client_data(client_socket):
        buf = b''
        lim = 8092
        while lim:
            buf += client_socket.recv(lim)
            lim = lim - len(buf)
            if b'\r\n\r\n' in buf:
                break
        return buf.decode('utf-8')

    @staticmethod
    def parse_request(request):
        patt = r'(?P<method>[A-Z]+) (?P<dir>/(\S+/)*)(?P<file>([\w\s\.\-]+\.\w+)?)(?P<addition>[^\s\/]*) HTTP'
        match = re.match(patt, unquote(request))
        return match.groupdict() if match else {}


def parse_args():
    parser = argparse.ArgumentParser(description='Simple synchronous http server. GET, HEAD methods only.')

    parser.add_argument('-m', '--master', type=str, default='localhost', help='Hostname, default - localhost.')
    parser.add_argument('-p', '--port', type=int, default=8888, help='Port, default - 8888.')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Server workers, default - 5.')
    parser.add_argument('-r', '--root', type=str, default='rootdir', help='DOCUMENT_ROOT directory.')
    parser.add_argument('-l', '--level', type=str, default='INFO', help='Logging level, default - INFO.')

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
        log.error('Server has been interrupted.')


if __name__ == '__main__':
    args = parse_args()
    set_logging(args.level)

    for _ in range(args.workers):
        worker = multiprocessing.Process(
            target=start_server,
            args=(
                args.master,
                args.port,
                args.root
            )
        )
        worker.start()
        




