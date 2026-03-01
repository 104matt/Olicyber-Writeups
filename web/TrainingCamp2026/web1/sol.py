import requests
#'pretty please :('
r = requests.options('http://10.45.1.2:4001/', params={'we_like': 'flags'}, headers={'give-me': 'the-flag', 'Content-Type': 'text/plain'}, cookies={'session_id': 'the_session'},  data='pretty please :(')
print(r.text)
