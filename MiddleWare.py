import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from utils import saveKey, loadKey


random_generator = Random.new().read
middleware_keys = RSA.generate(1024,random_generator)
saveKey(middleware_keys.export_key(),'mSK')
saveKey(middleware_keys.publickey().export_key(),'mPK')
print(loadKey('mPK'))
print(loadKey('mSK'))



