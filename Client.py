import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random


def saveKey(key,file):
    with open('keys/'+file,'wb') as key_file:
        key_file.write(key)

def loadKey(file):
    key = None
    with open('keys/'+file,'rb') as key_file:
        key = key_file.read()
    return key


random_generator = Random.new().read
clientKeys = RSA.generate(1024,random_generator)
saveKey(clientKeys.export_key(),'cSK')
saveKey(clientKeys.publickey().export_key(),'cPK')
print(loadKey('cPK'))
print(loadKey('cSK'))



