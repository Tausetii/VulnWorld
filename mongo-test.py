from pymongo import MongoClient

MONGODB_URL = "mongodb+srv://warrenmax256897_db_user:BOx2RmRB4bHE7NNJ@search.7qokngi.mongodb.net/?appName=search"
client = MongoClient(MONGODB_URL)

db = client['search-vuln-world']
collection = db['food']
login = db['login']

# CTF: off-menu row (same seed as main.py _seed_food_menu); flag is redeemed on Account, not stored here.
# collection.update_one(
#     {"ctf_menu_seed": "menu_nosql"},
#     {"$set": {"name": "Off-menu exploit platter", "price": 999999.0, "ctf_menu_seed": "menu_nosql"}},
#     upsert=True,
# )

login.insert_one({"username": "admin", "password": "admin"})
#collection.insert_one({"name": "Croissant", "price": 3.99})
#collection.insert_one({"name": "Muffin", "price": 3.99})
#collection.insert_one({"name": "Bagel", "price": 2.99})
#collection.insert_one({"name": "Water", "price": 0.99})
#collection.insert_one({"name": "Tea", "price": 2.49})

#for f in collection.find():
   # print(f)