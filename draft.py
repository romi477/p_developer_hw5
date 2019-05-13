import re




s0 = 'PUT dir/%70%61%67%65%2e%68%74%6d%6c HTTP'
s1 = 'PUT /httptest/dir2/dir3/page.html?arg1=value&arg2=value HTTP'
s2 = 'GET /httptest/space%20in%20name.txt HTTP'
s3 = 'GET /httptest/../../../../../../../../../../../../../etc/passwd HTTP'
s4 = 'GET /text..txt HTTP'
s5 = 'HEAD /httptest/dir2/page.html/ HTTP'
s6 = 'HEAD /httptest/dir2'

patt = r'(?P<method>\S*) (?P<dirs>/([^\.\s/]+/)*)(?P<file>\S*\.(txt|html|css||js|jpg|jpeg|png|gif|swf))?(?P<slash>/)?\S* HTTP'

l = [s0, s1, s2, s3, s4, s5, s6]

for i in l:
    match = re.search(patt, i)
    if match:
        print(i)
        print(match.group('method'))
        print(match.group('dirs'))
        print(match.group('file'))
        print(match.group('slash'))
        print('____________________')
        print()
    else:
        print('*****')