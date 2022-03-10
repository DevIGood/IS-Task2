from genericpath import isfile
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes

plaintext = 'I have a Samsung SD card'
key = 'WHAAAAAAAAAAAAAT' #Must be 16 char for AES128
iv =  get_random_bytes(16) #Must be 16 char for AES128
print(f'Your initialization vector is :{iv}')

def WrongInput():
    print('\nWrong input')


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

encryptedCBC = CBCencrypt(plaintext,key,iv)
print('encrypted with CBC:',encryptedCBC.decode())
decryptedCBC = CBCdecrypt(encryptedCBC,key,iv)
print('decrypted with CBC:', decryptedCBC.decode())

encryptedCFB = CFBencrypt(plaintext,key,iv)
print('encrypted with CFB:',encryptedCFB.decode())
decryptedCFB = CFBdecrypt(encryptedCFB,key,iv)
print('decrypted with CFB:', decryptedCFB.decode())


getinfo = int(input('1) Enter your own plaintext and key\n2) Get plaintext and key from file\n'))
if(getinfo == 1):
    choise = int(input('Choose your encryption or decryption method\n'+
    '1) ECB encryption\n' + '2) ECB decryption\n' +
    '3) CBC encryption\n' + '4) CBC decryption\n' +
    '5) CFB encryption\n' + '6) CFB decryption\n'
    ))
    if(choise == 1):
        plaintext = str(input("Enter your plaintext:"))
        encryptedECB = ECBencrypt(plaintext)
        print('encrypted with ECB:',encryptedECB.decode())
    elif(choise == 2):
        cyphertext = input("Enter your cypher text:")
        decryptedECB = ECBdecrypt(cyphertext)
        print('decrypted with ECB:',decryptedECB.decode())
    elif(choise == 3):
        plaintext = str(input("Enter your plaintext:"))
        key = str(input("Enter your plaintext:"))
        encryptedCBC = CBCencrypt(plaintext,key,iv)
        print('encrypted with CBC:',encryptedCBC.decode())
    elif(choise == 4):
        cyphertext = input("Enter your plaintext:")
        key = str(input("Enter your plaintext:"))
        decryptedCBC = CBCdecrypt(encryptedCBC,key,iv)
        print('decrypted with CBC:', decryptedCBC.decode())
    elif(choise == 5):
        plaintext = str(input("Enter your plaintext:"))
        key = str(input("Enter your plaintext:"))
        encryptedCFB = CFBencrypt(plaintext,key,iv)
        print('encrypted with CFB:',encryptedCFB.decode())
    elif(choise == 6):
        cyphertext = input("Enter your plaintext:")
        key = str(input("Enter your plaintext:"))
        decryptedCFB = CFBdecrypt(encryptedCFB,key,iv)
        print('decrypted with CFB:', decryptedCFB.decode())
    else:
        print("Wrong input")
    
elif(getinfo == 2):
    choise = int(input('Choose your encryption method\n'+
    '1) ECB encryption\n' +
    '2) CBC encryption\n' +
    '3) CFB encryption\n'
    ))
    if(choise == 1):
        plaintext = str(input("Enter your plaintext:"))
        encryptedECB = ECBencrypt(plaintext)
        tofile = open('encryptedtext.txt', "w")
        tofile.write(encryptedECB.decode())
        tofile.close()
        tofile = open('encryptedtext.txt', "r")
        cyphertext = tofile.readline()
        tofile.close()
        decryptedECB = ECBdecrypt(cyphertext)
        print('decrypted with ECB from file:',decryptedECB.decode())
    elif(choise == 2):
        plaintext = str(input("Enter your plaintext:"))
        key = str(input("Enter your plaintext:"))
        encryptedCBC = CBCencrypt(plaintext,key,iv)
        tofile = open('encryptedtext.txt', "w")
        tofile.write(encryptedCBC.decode())
        tofile.close()
        tofile = open('encryptedtext.txt', "r")
        cyphertext = tofile.readline()
        key = tofile.readline()
        tofile.close()
        decryptedCBC = CBCdecrypt(cyphertext,key,iv)
        print('decrypted with CBC from file:', decryptedCBC.decode())
    elif(choise == 3):
        plaintext = str(input("Enter your plaintext:"))
        key = str(input("Enter your plaintext:"))
        encryptedCFB = CFBencrypt(plaintext,key,iv)
        tofile = open('encryptedtext.txt', "w")
        tofile.write(encryptedCFB.decode())
        tofile.close()
        tofile = open('encryptedtext.txt', "r")
        cyphertext = tofile.readline()
        key = tofile.readline()
        tofile.close()
        decryptedCFB = CFBdecrypt(cyphertext,key,iv)
        print('decrypted with CFB from file:', decryptedCFB.decode())
else:
    print("Wrong input")