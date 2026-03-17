import requests
from bs4 import BeautifulSoup
url = 'http://web-15.challs.olicyber.it/'
req = requests.get(url)
html_doc= req.text

soup = BeautifulSoup(html_doc, 'html.parser')

for file in soup.find_all("link", href=True): 
    css = requests.get(url+file['href']).text 
    if "flag" in css: 
        print(css)
for file in soup.find_all("script", src=True): 
    js = requests.get(url+file['src']).text 
    if "flag" in js: 
        print(js)

