import requests
import string
from requests.auth import HTTPBasicAuth
import urllib.parse

basicAuth=HTTPBasicAuth('natas28', 'skrwxciAe6Dnb0VfFDzDEHcCzQmv3Gd4')

u="http://natas28.natas.labs.overthewire.org/index.php"

count = 0
headers = {'Content-Type': 'application/x-www-form-urlencoded' }

while count <= 16:
    data = "query=" + "A"*count
    response = requests.post(u, headers=headers, data=data, auth=basicAuth, verify=False, allow_redirects=True)
    print("{:02d}".format(count), "chars ", urllib.parse.unquote(response.url))
    count += 1

print("Done!\n")

for c in string.printable:
    data = "query=" + "A"*9 + c
    response = requests.post(u, headers=headers, data=data, auth=basicAuth, verify=False, allow_redirects=True)
    newUrl = urllib.parse.unquote(response.url)
    query = newUrl.split("=")[1]
    print(c, "\t", query)

    print("length: ", len(query))
    count += 1
