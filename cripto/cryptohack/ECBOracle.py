from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

flag = "8399707d033badaa41663890fe57858e"
newflag = ""
length = 25
char_dict = {chr(i): i for i in range(32, 127)}

for i in range(length):
    for j in char_dict.values():
        guess = j
        padded = pad(guess, 16)
        cipher = AES.new(padded, AES.MODE_ECB)
        if cipher == flag:
            newflag += chr(j)
            print(newflag)
            break