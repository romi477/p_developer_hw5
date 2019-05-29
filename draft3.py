import socket
from multiprocessing.dummy import Pool
import requests

urls = [
    'http://www.python.org',
    'http://www.python.org/about/',
    'http://www.onlamp.com/pub/a/python/2003/04/17/metaclasses.html',
    'http://www.python.org/doc/',
    'http://www.python.org/download/',
    'http://www.python.org/getit/',
    'http://www.python.org/community/',
    'https://wiki.python.org/moin/',
    'http://planet.python.org/',
    'https://wiki.python.org/moin/LocalUserGroups',
    'http://www.python.org/psf/',
    'http://docs.python.org/devguide/',
    'http://www.python.org/community/awards/'
    ]

pool = Pool(2)
res = []
def r(url):
    r = requests.get(url)
    print(r)


for i in pool.map(r, urls):
    res.append(i)
print('res', res)

# pool.close()
# pool.join()










# def handler(tup):
#     print('Handler start')
#     print(tup[0])
#     print(tup[1])
#     tup[0].close()
#     print('Handler stop')
#
#
#
# def serve_forever(server_socket):
#
#
#     pool = Pool(10)
#     queue = []
#
#     while True:
#         args = server_socket.accept()
#         queue.append(args)
#         pool.map(handler, queue)
#
#
#         pool.close()
#         pool.join()
#         print('------------------')
#
#
#
#
#
# if __name__ == '__main__':
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
#
#     server_socket.bind(('localhost', 5000))
#     server_socket.listen(5)
#     serve_forever(server_socket)






