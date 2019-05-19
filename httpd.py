import os
import re
import socket
import argparse
import mimetypes
import threading
import logging as log
import multiprocessing
from datetime import datetime

OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
METHOD_NOT_ALLOWED = 405

ERRORS = {
    400: '400 BAD_REQUEST',
    403: '403 FORBIDDEN',
    404: '404 NOT_FOUND',
    405: '405 METHOD_NOT_ALLOWED',
}


class Response:
    def __init__(self, request, root):
        self.request = request
        self.root = root
        
        self.methods = ['GET', 'HEAD']
        self.exts = ['', 'txt', 'html', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'swf']

    def execute(self):
        code, method, urn, message = self.parse_request()
        log.debug(f'Cleaned params: {code}; {method}; {urn}')

        data = self.generate_response(code, method, urn, message)
        
        return data

    def parse_request(self):
        log.debug('request: ', self.request )
        method = urn = message = ''
        patt = r'(?P<method>[A-Z]+) (?P<dir>/(\S+/)*)(?P<file>(\S+\.\w+)?)(?P<params>[^\.\s/]*) HTTP'
        match = re.match(patt, self.request)

        if match:
            query_dict = match.groupdict()
            log.debug(f'Request params: {query_dict}')
            method = query_dict['method']
            code, urn, message = self.get_response_data(query_dict)
        else:
            log.debug('Bad request! No matching!')
            code = BAD_REQUEST
        return code, method, urn, message

    def get_response_data(self, query):
        try:
            self.pre_validation(query)
        except Exception as ex:
            log.debug(ex)
            return BAD_REQUEST, '; '.join([f'{k}: {v}' for k, v in query.items()]), ex

        file = os.path.abspath('.') + '/' + self.root + query['dir'] + (query['file'] or 'index.html')

        if query['method'] not in self.methods:
            return METHOD_NOT_ALLOWED, file, f'method {query["method"]} not allowed'

        ext = query['file'].split('.')[-1]
        if ext not in self.exts:
            return FORBIDDEN, file, f'<*.{ext}> files not allowed for displaying'

        if '../' in query['dir']:
            return FORBIDDEN, file, '<../> document root escaping forbidden'

        if '.' in query['dir']:
            return NOT_FOUND, file, f'invalid directory name <{query["dir"]}>, dots in the directory path are not allowed'

        if not os.path.exists(file):
            return NOT_FOUND, file, 'make sure exactly that file is required'

        return OK, file, 'everything is ok'

    @staticmethod
    def pre_validation(query):
        if query['params'] and not query['params'].startswith('?') and '%' not in query['params']:
            raise ValueError(f'at least query arguments <{query["params"]}> have some mistakes')
        query['file'] = re.sub(r'%\d\d', ' ', query['file'])

    def generate_response(self, code, method, urn, message):
        headers = self.get_headers(code, urn)
        
        if code == 200:
            if method == 'GET':
                with open(urn, 'rb') as body:
                    return b'\r\n\r\n'.join([headers, body.read()])
            return headers
            
        return b'\r\n\r\n'.join([headers, f'{ERRORS.get(code, "500 INTERNAL_ERROR")}:\n\n{urn}\n\nHINT: {message}'.encode(encoding='utf-8')])

    def get_headers(self, code, urn):
        cont_len = os.path.getsize(urn) if os.path.exists(urn) else ''
        cont_type = mimetypes.guess_type(urn)[0] if os.path.exists(urn) else ''

        items = [
            f'HTTP/1.1 {code}',
            f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            'Server: Simple HTTP server',
            f'Content-Length: {cont_len}',
            f'Content-Type: {cont_type}',
            'Connection: close'
        ]
        return ('\r\n'.join(items)).encode(encoding='utf-8')


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
        else:
            self.server_socket.listen(5)
            log.debug(f'Server has been started on <{self.host}: {self.port}>.')
            self.accept_client()

    def accept_client(self):
        while True:
            log.debug('Waiting for client.')
            client_socket, client_addr = self.server_socket.accept()
            log.debug(f'New connection: {client_socket}')
            try:
                clients_handler = threading.Thread(target=self.clients_handler, args=(client_socket, client_addr))
            except Exception as ex:
                log.debug(ex)
                client_socket.close()
            else:
                log.debug(f'New process for {client_addr[1]} has been started')
                clients_handler.start()

        # return self.clients_handler(client_socket, client_addr)

    def clients_handler(self, client_socket, client_addr):

        log.debug("Waiting for client's message:")
        client_query = self.get_request(client_socket)
        log.debug(f'Message from {client_addr[1]}:\n{client_query}')

        # client_socket.send('Server got it!\n'.encode(encoding='utf-8'))
        # client_socket.close()

        response = Response(client_query, self.root)
        data = response.execute()

        client_socket.send(data)
        client_socket.close()
        # log.debug(f'Client socket {client_addr[1]} has been closed')
        # log.debug('----------')

    @staticmethod
    def get_request(client_socket):
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
        worker = multiprocessing.Process(target=start_server, args=(args.master, args.port, args.root))
        worker.start()




