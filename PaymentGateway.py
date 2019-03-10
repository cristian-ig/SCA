import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Utils import saveKey, loadKey
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from  Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import pickle
import socket



def decryptAESKey(aes_encrypted_key):
    merchant_secretKey = loadKey('pgSK')
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(merchant_secretKey))
    aes_decrypted_key = cipher_rsa.decrypt(aes_encrypted_key)

    return aes_decrypted_key
random_generator = Random.new().read
pgKeys = RSA.generate(1024,random_generator)
saveKey(pgKeys.export_key(),'pgSK')
saveKey(pgKeys.publickey().export_key(),'pgPK')
print(loadKey('pgPK'))
print(loadKey('pgSK'))

PORT = 6024
TCP_IP  = '127.0.0.1'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, PORT))
s.listen(1)

conn, addr = s.accept()

aes_encryptedKey = conn.recv(4096)

aes_decryptedKey = decryptAESKey(aes_encryptedKey)

data_from_merchant = conn.recv(4096)
data_from_merchant = pickle.loads(data_from_merchant)
iv = data_from_merchant['iv']
encrypted_data = data_from_merchant['DATA']
cypher = AES.new(aes_decryptedKey,AES.MODE_CBC,iv)
decrypted_item = unpad(cypher.decrypt(encrypted_data),AES.block_size)

decrypted_data = pickle.loads(decrypted_item)

PM = pickle.loads(decrypted_data['PM'][0])
SigM = decrypted_data['SigM']
print('PM',PM )
verification = None
try:
    key = RSA.import_key(loadKey("mPK"))
    pkcs1_15.new(key).verify(SHA256.new(bin(int.from_bytes(decrypted_data['USigM'],byteorder='big')).encode("UTF-8")), (SigM))
    verification = True
except (ValueError, TypeError):
    verification = False


if verification:
    uSigPg = {"Response":'True',"SID":PM['SID'],"Amount":PM['Amount']}
    key = RSA.import_key(loadKey('pgSK'))
    response_for_merchant = {"Response":"True","SID":PM['SID'],"SigPG":pkcs1_15.new(key).sign(SHA256.new(bin(int.from_bytes(pickle.dumps(uSigPg),byteorder='big')).encode("UTF-8")))}

    cypher = AES.new(aes_decryptedKey,AES.MODE_CBC)
    response = {"DATA":cypher.encrypt(pad(pickle.dumps(response_for_merchant),AES.block_size)),"iv":cypher.iv}
    print("IV",cypher.iv)
    pickle_response = pickle.dumps(response)
    print(len(pickle_response))
    conn.send(pickle_response)
print("Verification", verification)




