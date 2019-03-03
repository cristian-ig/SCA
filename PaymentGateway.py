import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from utils import saveKey, loadKey


random_generator = Random.new().read
pgKeys = RSA.generate(1024,random_generator)
saveKey(pgKeys.export_key(),'pgSK')
saveKey(pgKeys.publickey().export_key(),'pgPK')
print(loadKey('pgPK'))
print(loadKey('pgSK'))





