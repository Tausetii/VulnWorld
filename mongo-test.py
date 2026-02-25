from pymongo import MongoClient

MONGODB_URL = "mongodb+srv://warrenmax256897_db_user:BOx2RmRB4bHE7NNJ@search.7qokngi.mongodb.net/?appName=search"
client = MongoClient(MONGODB_URL)

db = client['search-vuln-world']
collection = db['food']

#collection.insert_one({"name": "Croissant", "price": 3.99})
#collection.insert_one({"name": "Muffin", "price": 3.99})
#collection.insert_one({"name": "Bagel", "price": 2.99})
#collection.insert_one({"name": "Water", "price": 0.99})
#collection.insert_one({"name": "Tea", "price": 2.49})

#for f in collection.find():
   # print(f)