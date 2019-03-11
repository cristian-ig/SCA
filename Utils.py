from tinydb import TinyDB, Query


def saveKey(key, file):
    with open('keys/' + file, 'wb') as key_file:
        key_file.write(key)


def loadKey(file):
    with open('keys/' + file, 'rb') as key_file:
        key = key_file.read()
    return key


def getDBName(dbn):
    dbname = None
    dbn = dbn.lower()
    if dbn == "m":
        dbname = "merchant"
    elif dbn == "c":
        dbname = "client"
    elif dbn == "pg":
        dbname = "payment"

    return dbname


def insert_SID_SSID(SID, SSID, database):
    databasename = getDBName(database)
    if databasename is None:
        print("INVALID DATABASE NAME! TRY: M, C, PG")
        return -1
    database = TinyDB(databasename)
    database.insert({"SID": SID, "SSID": SSID})


def check_valid_SID(SID_to_be_checked, database):
    databasename = getDBName(database)
    if databasename is None:
        print("INVALID DATABASE NAME! TRY: M, C, PG")
        return -1
    database = TinyDB(databasename)
    query = Query()
    if len(database.search(query.SID == SID_to_be_checked)) > 0:
        return True
    else:
        return False


def check_valid_SSID(SSID_to_be_checked, database):
    databasename = getDBName(database)
    if databasename is None:
        print("INVALID DATABASE NAME! TRY: M, C, PG")
        return -1
    database = TinyDB(databasename)
    query = Query()
    if len(database.search(query.SSID == SSID_to_be_checked)) > 0:
        return True
    else:
        return False

def purge_database(dbname):
    db = TinyDB(getDBName(dbname)).purge()
    
def sign_message(key):
    pass


def get_money_from_card(card_number):
    db = TinyDB("bank.json")
    q = Query()
    return db.search(q.card == card_number)[0]["money"]


def withdraw_money_from_card(card_number, amount):
    db = TinyDB("bank.json")
    q = Query()
    return db.update({"money": get_money_from_card(card_number) - amount}, q.card == card_number)



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
