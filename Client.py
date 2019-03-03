import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from utils import saveKey, loadKey
import socket

# random_generator = Random.new().read
# clientKeys = RSA.generate(1024,random_generator)
# saveKey(clientKeys.export_key(),'cSK')
# saveKey(clientKeys.publickey().export_key(),'cPK')
# print(loadKey('cPK'))
# print(loadKey('cSK'))


merchant_publicKey = loadKey('mPK')

aes_bytekey = get_random_bytes(32)

cipher_rsa = PKCS1_OAEP.new(RSA.import_key(merchant_publicKey))
merchant_encrypted_key = cipher_rsa.encrypt(aes_bytekey)

aes_key = AES.new(aes_bytekey,AES.MODE_CBC)

print(merchant_encrypted_key)



# print("AES_KEY",aes_key.hexdigest())
print("MERCHANt",merchant_publicKey)
TCP_IP = '127.0.0.1'
PORT = 6001

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.connect((TCP_IP,PORT))

server.send(merchant_encrypted_key)


