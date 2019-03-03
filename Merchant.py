import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from utils import saveKey, loadKey
import socket


def signSessionId(aes_encrypted_key):
    merchant_secretKey = loadKey('mSK')
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(merchant_secretKey))
    aes_decrypted_key = cipher_rsa.decrypt(aes_encrypted_key)
    print(aes_decrypted_key)


random_generator = Random.new().read
middleware_keys = RSA.generate(1024,random_generator)
saveKey(middleware_keys.export_key(),'mSK')
saveKey(middleware_keys.publickey().export_key(),'mPK')
print(loadKey('mPK'))
print(loadKey('mSK'))



TCP_IP = '127.0.0.1'
PORT = 6001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, PORT))
s.listen(1)

conn, addr = s.accept()
print(addr,"Connected")
while 1:
    data = conn.recv(1024)
    if data is not None:
        signSessionId(data)
    # conn.send('aaa')

conn.close()