import requests

req = requests.session()
body = {"username":"admin","password":"admin"}

csrf = (req.post("http://web-11.challs.olicyber.it/login", json=body)).text
r=req.post("http://web-11.challs.olicyber.it/login", json=body)
print(csrf)
#print(r.json())
#for i in range(4):
    #f=req.get("http://web-11.challs.olicyber.it/flag_piece?index=", index=i)


