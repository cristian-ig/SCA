def saveKey(key, file):
    with open('keys/' + file, 'wb') as key_file:
        key_file.write(key)


def loadKey(file):
    key = None
    with open('keys/' + file, 'rb') as key_file:
        key = key_file.read()
    return key


def sign_message(key):
    pass


"""
Generam pereche de chei RSA pentru C, M, PG
Fiecare entitate are acces la cheia publica a celorlalte 
C genereaza cheie AES pentru vb cu M
C genereaza cheie AES pentru vb cu PG
M genereaza cheie AES pentru vb cu PG
0. C preia datele comenzii, card, amount, produs etc
1. C trimite lui M cheia AES criptata cu cheia publica RSA a lui M
2. M trimite lui C un SID (SessionID) si il semneaza (cumva) criptat AES-cm
3. C trimite {PM, PO} criptate cu AES-cm lui M
    unde PM = {PI, PI semnat de C} criptat AES-pg (adica trimitem cheia AEA pentru a vb cu PG criptata cu cheia lui publica)
    unde PO = {OrderDescription, SID, Amount, SigC(OrderDescription, SID, Amount)}
    unde PI = {CardNumber, CardExp, CCode, SID, Amount, PublicKey a lui C, Nonce (number used onace) si M? dafaq is M}
4. M trimite lui PG {PM, SigM(Sid, PubK, Amount) criptate AES-mpg
5. PG ii trimtie lui M {Response (true sau false), SID, SigPG(Response, SID, Amount, Nonce)} criptate AES-mpg
6. M ii trimite lui C {Response, SID, SigPG(Response, SID, Amount, NC)} criptate AES-cm

"""
