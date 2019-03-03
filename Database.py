from tinydb import TinyDB, Query

merchant = TinyDB('merchant.json')

merchant.purge()  # distruge tot din db

merchant.insert({'SID': "12345"})  # Adaugam un obiect in db

query = Query()
print("found: ",
      merchant.search(query.SID == '12345'))  # cautam asa: Q.proprietate == "ceva" sau > ceva daca e numar etc..

print(merchant.all())
