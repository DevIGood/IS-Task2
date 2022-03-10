from multiprocessing.connection import wait
import base64
from time import sleep
from xml.etree.ElementTree import tostring 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes

plaintext = 'I have a Samsung SD card'
key = 'WHAAAAAAAAAAAAAT' #Must be 16 char for AES128
iv =  get_random_bytes(16) #Must be 16 char for AES128
print(f'Your initialization vector is :{iv}')

def WrongInput():
    print('\nWrong input')
    sleep(2)


def ECBencrypt(plaintext):
    plaintext = pad(plaintext.encode(),16)
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext))
def ECBdecrypt(enc):
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    return unpad(cipher.decrypt(enc),16)

def CBCencrypt(plaintext,key,iv):
    plaintext= pad(plaintext.encode(),16)
    cipher = AES.new(key.encode(),AES.MODE_CBC,iv)
    return base64.b64encode(cipher.encrypt(plaintext))
def CBCdecrypt(enc,key,iv):
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc),16)

def CFBencrypt(plaintext,key,iv):
    plaintext= bytes(plaintext.encode())
    cipher = AES.new(key.encode(),AES.MODE_CFB,iv)
    return base64.b64encode(cipher.encrypt(plaintext))
def CFBdecrypt(enc,key,iv):
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode(), AES.MODE_CFB, iv)
    return cipher.decrypt(enc)

encryptedECB = ECBencrypt(plaintext)
print('encrypted with ECB:',encryptedECB.decode())
decryptedECB = ECBdecrypt(encryptedECB)
print('decrypted with ECB:',decryptedECB.decode())

print("\n")

encryptedCBC = CBCencrypt(plaintext,key,iv)
print('encrypted with CBC:',encryptedCBC.decode())
decryptedCBC = CBCdecrypt(encryptedCBC,key,iv)
print('decrypted with CBC:', decryptedCBC.decode())

print("\n")

encryptedCFB = CFBencrypt(plaintext,key,iv)
print('encrypted with CFB:',encryptedCFB.decode())
decryptedCFB = CFBdecrypt(encryptedCFB,key,iv)
print('decrypted with CFB:', decryptedCFB.decode())


getinfo = input ('1) Get plaintext and key from file\n2) Enter your own plaintext and key\n'
)
choise = input ('Choose your encryption or decryption method\n'+
'1) ECB encryption\n' + '2) ECB decryption\n' +
'3) CBC encryption\n' + '4) CBC decryption\n' +
'5) CFB encryption\n' + '6) CFB decryption\n'
)
if(choise == 1):
