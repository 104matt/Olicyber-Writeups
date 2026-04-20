import requests
import bs4

s = requests.Session()

HTML_DOC = s.get("http://10.45.1.2:8000/").text
soup = bs4.BeautifulSoup(HTML_DOC, "html.parser")
print(HTML_DOC)
r = s.post("http://10.45.1.2:8000/solve", json={"solution": ""})
print(r.text)
#while(True):
