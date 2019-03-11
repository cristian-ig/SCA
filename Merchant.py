from Crypto.PublicKey import RSA
import socket

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

from Utils import loadKey


def decryptAESKey(aes_encrypted_key):
    merchant_secretKey = loadKey('mSK')
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(merchant_secretKey))
    aes_decrypted_key = cipher_rsa.decrypt(aes_encrypted_key)

    return aes_decrypted_key

def signSessionId(aes_encrypted_key):
    aes_decrypted_key = decryptAESKey(aes_encrypted_key)

    SID = get_random_bytes(8)

    SID_hash = SHA256.new(SID)
    key = RSA.import_key(loadKey('mSK'))

    SSID = pkcs1_15.new(key).sign(SID_hash)

    # print("Signed hash\n", SSID)
    # key = RSA.import_key(loadKey('mPK'))
    # print("Verify",pkcs1_15.new(key).verify(SID_hash,SSID))

    # Return session id and signed session id with merchant private key
    return (SID, SSID)

def decryptAES_item(item,aes_encrypted_key,iv):

    aes_decrypted_key = decryptAESKey(aes_encrypted_key)
    cipher = AES.new(aes_decrypted_key,AES.MODE_CBC,iv)

    item_decrypted = unpad(cipher.decrypt(item),AES.block_size)

    return item_decrypted



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
    aes_encrypted_key = data
    SID, SSID = signSessionId(aes_encrypted_key)
    msg = pickle.dumps({'SID': SID, 'SSID': SSID})
    conn.send(msg)


    data = pickle.loads(conn.recv(9096))
    PO = decryptAES_item(data["PO"], aes_encrypted_key, data["IV1"])


    PM = pickle.loads(decryptAES_item(data["PM"], aes_encrypted_key, data["IV2"]))
    PI = pickle.loads(PM[0])


    mPK = loadKey("mPK")
    mSK = loadKey("mSK")

    signedRespone = {"SID":SID,"mPK":mPK,"Amount":PI['Amount']}
    pickle_signedR = pickle.dumps(signedRespone)
    pickle_signedR_hash  = SHA256.new(bin(int.from_bytes(pickle_signedR,byteorder='big')).encode("UTF-8"))
    key = RSA.import_key(mSK)

    response_for_pg = {"PM":PM,"USigM":pickle_signedR,"SigM":pkcs1_15.new(key).sign(pickle_signedR_hash)}

    pg_rsa = RSA.import_key(loadKey('pgPK'))
    cypher = PKCS1_OAEP.new(pg_rsa)

    pickle_response_for_pg = pickle.dumps(response_for_pg)







server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((TCP_IP, 6024))
# s.send(encrypted_response_for_pg)

paymentGateway_publicKey = loadKey('pgPK')

aes_bytekey = get_random_bytes(32)

cipher_rsa = PKCS1_OAEP.new(RSA.import_key(paymentGateway_publicKey))
merchant_encrypted_key = cipher_rsa.encrypt(aes_bytekey)
server.send(merchant_encrypted_key)

aes_key = AES.new(aes_bytekey, AES.MODE_CBC)
encrypted_pickle_response_for_pg = aes_key.encrypt(pad(pickle_response_for_pg,AES.block_size))
iv = aes_key.iv
response = {'DATA':encrypted_pickle_response_for_pg,'iv':iv}
server.send(pickle.dumps(response))

pg_response = server.recv(4096)
print(len(pg_response))
pg_response_dict =pickle.loads(pg_response)
print("RESPONSE DICT",pg_response_dict)

cypher = AES.new(aes_bytekey,AES.MODE_CBC,pg_response_dict['iv'])

pg_response_decrypted = pickle.loads(unpad(cypher.decrypt(pg_response_dict['DATA']),AES.block_size))
uSigPG = {'Response':pg_response_decrypted['Response'],"SID":pg_response_decrypted["SID"],"Amount":pickle.loads(PM[0])['Amount']}

verification = None
try:
    key = RSA.import_key(loadKey("pgPK"))
    pkcs1_15.new(key).verify(SHA256.new(bin(int.from_bytes(pickle.dumps(uSigPG),byteorder='big')).encode("UTF-8")), (pg_response_decrypted['SigPG']))
    verification = True
except (ValueError, TypeError):
    verification = False

if verification:
    UsigPg = {'Response':pg_response_decrypted['Response'],'SID':pg_response_decrypted['SID'],'Amount':pickle.loads(PM[0])['Amount']}
    rsa_key = RSA.import_key(loadKey('mSK'))
    response_for_client = {'Response':pg_response_decrypted['Response'],'SID':pg_response_decrypted['SID'],'SigPG':pkcs1_15.new(rsa_key).sign(SHA256.new(bin(int.from_bytes(pickle.dumps(UsigPg),byteorder='big')).encode("UTF-8")))}
    conn.send(pickle.dumps(response_for_client))
print(verification)

print("PG RESPONSE DECRYPTED",pg_response_decrypted)

