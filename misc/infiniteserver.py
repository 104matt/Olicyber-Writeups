import requests
from bs4 import BeautifulSoup

s = requests.Session()
html_doc= s.get("http://infinite.challs.olicyber.it/")



# print(html_doc.text)

while True:
    soup = BeautifulSoup(html_doc.text, 'html.parser')

    titles = str(soup.find_all('title'))

    if("GRAMMAR" in titles):
        print("grammar")
        p = str(soup.p).split()
        countlettere = 0
        lettera = p[1].strip("\"") #da [""o""] a o
        if '"?</p>' in p:
            parola = p[6].strip("\"")
        else:
            parola = p[6][:-5].strip("\"")

        for i in range(len(parola)):
            if(lettera in parola[i]):
                countlettere+=1 
        r = s.post("http://infinite.challs.olicyber.it/", data={"letter":f"{countlettere}","submit":"Submit"})
        html_doc= r
        print(r.text)
        print(p)
        print(f"{lettera} in {parola} è {countlettere}")

    elif("MATH" in titles):
        print("math")
        p = str(soup.p).split()
        add1 = int(p[2])
        add2 = int(p[4][:-5])
        sum = add1+add2
        r= s.post("http://infinite.challs.olicyber.it/", data={"sum":f"{sum}"})
        html_doc= r
        #print(f"{add1}+{add2} fa {sum}")
        print(r.text)
        
    elif("ART" in titles):
        print("art")
        p = str(soup.p).split()
        color = ""
        print(p)
        if "Verde?</p>" in p:
            print("verde")
            color = "Verde"
        elif "Rosso?</p>" in p:
            print("rosso")
            color = "Rosso"
        elif "Blu?</p>" in p:
            print("blu")
            color = "Blu"
        r = s.post("http://infinite.challs.olicyber.it/", data={f"{color}":""})
        html_doc= r
        print(r.text)
    else:
        print(html_doc)
        break
    