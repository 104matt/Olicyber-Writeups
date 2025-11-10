import requests

req = requests.get("http://iforgot.challs.olicyber.it/")

print(req.text)