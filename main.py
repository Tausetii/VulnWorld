import re

from flask import Flask, render_template, redirect, request
from pymongo import MongoClient

MONGODB_URL = "mongodb+srv://warrenmax256897_db_user:BOx2RmRB4bHE7NNJ@search.7qokngi.mongodb.net/?appName=search"
client = MongoClient(MONGODB_URL)

db = client['search-vuln-world']
collection = db['food']

app = Flask(__name__)

NOSQL_PAYLOAD_PATTERNS = [
    r"\$ne",
    r"\$gt",
    r"\$gte",
    r"\$lt",
    r"\$lte",
    r"\$or",
    r"\$and",
    r"\$where",
    r"\$regex",
    r"\$exists",
    r"\{.*\}",
    r"null",
    r"true|false",
]

MOCK_CHALLENGE_RESULTS = [
    {"name": "Admin Combo Platter", "price": 0.0},
    {"name": "Staff-Only Energy Stack", "price": 0.01},
    {"name": "Internal Test Meal", "price": 0.02},
]

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

# ---------------------------------------------------------------------------
# VulnWorld – Gaming cafe (intentionally vulnerable for pentest practice)
# Site structure:
#   /           → redirects to /welcome
#   /welcome    → gateway home (links to Menu, About, Contact)
#   /menu       → food menu page (uses /search/<budget>)
#   /about      → about the owners
#   /contact    → contact information
#   /events     → special events held at the cafe
#   /chat       → AI chatbot (logic to be added later)
#   /search/<budget> → API: food items within budget (used by menu page)
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    return redirect('/welcome')


@app.route('/welcome')
def welcome():
    """Gateway home – entry point to the rest of the site."""
    return render_template('welcome.html')


@app.route('/menu')
def menu():
    """Food menu – search items by budget (uses /search/<budget>)."""
    return render_template('menu.html')


@app.route('/about')
def about():
    """About the owners of the gaming cafe."""
    return render_template('about.html')


@app.route('/contact')
def contact():
    """Contact information."""
    return render_template('contact.html')


@app.route('/events')
def events():
    """Special events held at the gaming cafe."""
    return render_template('events.html')


@app.route('/chat')
def chat():
    """AI chatbot – logic to be added later."""
    return render_template('chatbot.html')


@app.route('/search/<budget>', methods=['GET'])
def search_food_items(budget):
    """API: returns food items from DB with price <= budget."""
    candidate = budget.strip()
    lowered = candidate.lower()

    if any(re.search(pattern, lowered) for pattern in NOSQL_PAYLOAD_PATTERNS):
        app.logger.warning(
            "NoSQL-like input detected from %s: %r",
            request.remote_addr,
            budget,
        )
        return MOCK_CHALLENGE_RESULTS

    try:
        max_budget = float(candidate)
    except ValueError:
        return []

    results = []
    for item in collection.find():
        if item['price'] <= max_budget:
            item["_id"] = str(item["_id"])
            results.append(item)
    return results


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050)

