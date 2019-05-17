from http import client
import socket
# import unittest
# import requests
#
# r = requests.get('http://localhost:8888/httptest/dir2/')

host = "localhost"
port = 8888


conn = client.HTTPConnection(host, port)

conn.request("GET", '/')
r = conn.getresponse()

data = r.read()
print(data)
print('headers:\n', r.headers)
print(type(r.headers))
print(r.status, r.reason)
server = r.getheader("Server")


# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((host, port))
# s.sendall(b"\n")
# s.close()
#
# conn.close()