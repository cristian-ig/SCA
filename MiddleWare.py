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
middleware_keys = RSA.generate(1024,random_generator)
saveKey(middleware_keys.export_key(),'mSK')
saveKey(middleware_keys.publickey().export_key(),'mPK')
print(loadKey('mPK'))
print(loadKey('mSK'))



