import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Utils import saveKey, loadKey
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import socket
import json
import pickle

# random_generator = Random.new().read
# clientKeys = RSA.generate(1024,random_generator)
# saveKey(clientKeys.export_key(),'cSK')
# saveKey(clientKeys.publickey().export_key(),'cPK')
# print(loadKey('cPK'))
# print(loadKey('cSK'))


# print(merchant_encrypted_key)


# print("AES_KEY",aes_key.hexdigest())
# print("MERCHANt",merchant_publicKey)
TCP_IP = '127.0.0.1'
PORT = 6001

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((TCP_IP, PORT))
"""
    Send aes key encrypted with merchent publickey rsa
"""
#######################################################################
merchant_publicKey = loadKey('mPK')

aes_bytekey = get_random_bytes(32)

cipher_rsa = PKCS1_OAEP.new(RSA.import_key(merchant_publicKey))
merchant_encrypted_key = cipher_rsa.encrypt(aes_bytekey)

aes_key = AES.new(aes_bytekey, AES.MODE_CBC)
server.send(merchant_encrypted_key)

#####################################################################

"""
    Recieve the SID and SSID and verify them
    
"""
#######################################################################################
signature = server.recv(3024)
print("reciving..", signature)
# print(len(signature))
signature = pickle.loads(signature)
print(signature)

key = RSA.import_key(loadKey('mPK'))

verification = None
try:
    pkcs1_15.new(key).verify(SHA256.new(signature['SID']), (signature['SSID']))
    verification = True
except (ValueError, TypeError):
    verification = False

print(verification)

#########################################################################################
"""
    
    Criptam PM si PO cu aes si le trimitem merchantului

"""
########################################################################################

PI = {'CardNumber': 'XXXX-XXXX-XXXX-XXXX', 'CardExp': '07/20', 'CCode': 764,'Amount':1000,'SID':signature['SID'], 'cPK': loadKey('cPK')}
PI_bytes = pickle.dumps(PI)
print("PI_Bytes", PI_bytes)

PM = (PI_bytes, pkcs1_15.new(RSA.import_key(loadKey('cSK'))).sign(SHA256.new(PI_bytes)))

PM_bytes = pickle.dumps(PM)

PO_withoutsig = {'OrderDescription': 'Some description', 'SID': signature['SID'], 'Amount': 9000}
PO_withoutsig_bytes = pickle.dumps(PO_withoutsig)

PO = {'OrderDescription': 'Some description', 'SID': signature['SID'], 'Amount': 9000,
      'SigC': pkcs1_15.new(RSA.import_key(loadKey('cSK'))).sign(SHA256.new(PO_withoutsig_bytes))}
PO_bytes = pickle.dumps(PO)
print("PICKLE_LOADS\n", pickle.loads(PO_bytes))

aes_key = AES.new(aes_bytekey, AES.MODE_CBC)

PO_encrypted = aes_key.encrypt(pad(PO_bytes, AES.block_size))
iv1 = aes_key.iv
# print("iv1,", iv1)
# server.send(iv)
# server.send(PO_encrypted)

aes_key = AES.new(aes_bytekey, AES.MODE_CBC)

PM_encrypted = aes_key.encrypt(pad(PM_bytes, AES.block_size))
iv2 = aes_key.iv
# print("iv2,", iv2)
server.send(pickle.dumps({"IV2": iv2, "PM": PM_encrypted, "IV1": iv1, "PO": PO_encrypted}))
print("hi", {"IV2": iv2, "PM": PM_encrypted, "IV1": iv1, "PO": PO_encrypted})

final_respone = server.recv(4096)
final_respone_dict = pickle.loads(final_respone)
print("Final response ",final_respone_dict)
USigPG = {"Response":final_respone_dict['Response'],"SID":final_respone_dict["SID"],"Amount":PI['Amount']}
verification = None
try:
    key = RSA.import_key(loadKey("mPK"))
    UsigPg = {'Response': final_respone_dict['Response'], 'SID': final_respone_dict['SID'],
              'Amount': pickle.loads(PM_bytes[0])['Amount']}
    pkcs1_15.new(key).verify(SHA256.new(bin(int.from_bytes(pickle.loads(USigPG),byteorder='big')).encode("UTF-8")), (final_respone_dict['SigPG']))
    verification = True
except (ValueError, TypeError):
    verification = False
print("Verification",verification)
# server.send(iv)
# server.send(PM_encrypted)


########################################################################################
