import re


s = 'space%20in%20name.txt'
s1 = ''
patt=r'(?P<space>%\d\d)'
res = re.search(patt, s)
print(res)




lst = [
    'HEAD /page.ico HTTP',
    'HEAD /httptest/dir2/page._html/ HTTP',
    'PUT /dir/%70%61%67%65%2e%68%74%6d%6c HTTP',
    'PUT /httptest/dir2/dir3/page.html?arg1=value&arg2=value HTTP',
    'GET /httptest/space%20in%20name.txt HTTP',
    'GET /httptest/../../../../../../../../../../../../../etc/passwd HTTP',
    'GET /text...txt HTTP',
    'HEAD /httptest/dir2 HTTP'
]

patt = r'(?P<method>[A-Z]+) (?P<dir>/(\S+/)*)(?P<file>(\S+\.(txt|html|css|js|jpg|jpeg|png|gif|swf))?)(?P<addition>[^\.\s]*) HTTP'


for s in lst:
    match = re.search(patt, s)
    print(s)
    print()
    if match:
        print('method', match.group('method'))
        print('dirs', match.group('dir'))
        print('file', match.group('file'))
        print('addition', match.group('addition'))
        print()
    else:
        print('*****')
    print('____________________')
    print()
