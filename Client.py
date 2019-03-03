import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from utils import saveKey, loadKey

random_generator = Random.new().read
clientKeys = RSA.generate(1024,random_generator)
saveKey(clientKeys.export_key(),'cSK')
saveKey(clientKeys.publickey().export_key(),'cPK')
print(loadKey('cPK'))
print(loadKey('cSK'))



