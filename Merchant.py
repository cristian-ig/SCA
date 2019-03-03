import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
import json
import pickle

from Utils import saveKey, loadKey
import socket


def signSessionId(aes_encrypted_key):
    merchant_secretKey = loadKey('mSK')
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(merchant_secretKey))
    aes_decrypted_key = cipher_rsa.decrypt(aes_encrypted_key)
    print(aes_decrypted_key)

    SID = get_random_bytes(8)
    SID_hash = SHA256.new(SID)
    key = RSA.import_key(loadKey('mSK'))
    # print("Session ID\n", SID)

    # print("Initial hash\n", SID_hash)
    SSID = pkcs1_15.new(key).sign(SID_hash)

    # print("Signed hash\n", SSID)
    # key = RSA.import_key(loadKey('mPK'))
    # print("Verify",pkcs1_15.new(key).verify(SID_hash,SSID))

    # Return session id and signed session id with merchant private key
    return (SID, SSID)


# random_generator = Random.new().read
# middleware_keys = RSA.generate(1024,random_generator)
# saveKey(middleware_keys.export_key(),'mSK')
# saveKey(middleware_keys.publickey().export_key(),'mPK')
# print(loadKey('mPK'))
# print(loadKey('mSK'))


TCP_IP = '127.0.0.1'
PORT = 6001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, PORT))
s.listen(1)

conn, addr = s.accept()
print(addr, "Connected")
data = None
# while 1:
data = conn.recv(3024)
if len(data) > 0:
    # print("Len", data)
    SID, SSID = signSessionId(data)
    msg = pickle.dumps({'SID': SID, 'SSID': SSID})
    print("sending..", msg)
    conn.send(msg)

    # conn.send('aaa')

conn.close()
