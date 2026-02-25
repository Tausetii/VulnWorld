from flask import Flask, render_template
from pymongo import MongoClient

MONGODB_URL = "mongodb+srv://warrenmax256897_db_user:BOx2RmRB4bHE7NNJ@search.7qokngi.mongodb.net/?appName=search"
client = MongoClient(MONGODB_URL)

db = client['search-vuln-world']
collection = db['food']

app = Flask(__name__)

# data = [{
#
 #   "name" : "Coffee",
#    "price" : 2.99
#},
#{
#    "name" : "Croissant",
#    "price" : 3.99
#},
#{
#    "name" : "Muffin",
#    "price" : 3.99
#},
#{
#    "name" : "Bagel",
#    "price" : 2.99
#},
#{
#    "name" : "Water",
#    "price" : 0.99
##},
#{
#    "name" : "Tea",
#    "price" : 2.49
#}#

#]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/welcome')
def welcome():
    return '<html><body><h1>Welcome to the Flask App!</h1></body></html>'

@app.route('/search/<budget>', methods=['GET'])
def search_food_items(budget):
    results = []
    for item in collection.find():
        if item['price'] <= float(budget):
            item["_id"] = str(item["_id"])
            results.append(item)
    return results

app.run(host = '0.0.0.0', port = 5050)

