import requests
import json
req = requests.session()
body = {"username":"admin","password":"admin"}

csrf = json.loads(req.post("http://web-11.challs.olicyber.it/login", json=body).text)["csrf"]
print(csrf)
for i in range(4):
    f= json.loads(req.get("http://web-11.challs.olicyber.it/flag_piece?index=" + str(i) + "&csrf=" + csrf).text)
    csrf = f["csrf"]
    print(f)



