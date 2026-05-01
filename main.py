import os
import re
from datetime import datetime, timezone

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from werkzeug.security import check_password_hash, generate_password_hash

MONGODB_URL = "mongodb+srv://warrenmax256897_db_user:BOx2RmRB4bHE7NNJ@search.7qokngi.mongodb.net/?appName=search"
client = MongoClient(MONGODB_URL)

db = client['search-vuln-world']
collection = db['food']
login_collection = db['login']
flag_solves = db['flag_solves']

try:
    flag_solves.create_index([("username", 1), ("flag_id", 1)], unique=True)
except Exception:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-vulnworld-session-key")

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
    {
        "name": "Off-menu exploit platter – VulnWorld{n0sql_1nj3ct_m3nu_3262026}",
        "price": 0.03,
    },
]

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-.]{2,64}$")

# CTF: flag_id -> display name, points, and secret string (server-side only).
CTF_FLAGS = {
    "test": {
        "name": "VulnWorld{Test}",
        "points": 10,
        "secret": "VulnWorld{Test}",
    },
    "admin_endpoint": {
        "name": "Admin Endpoint",
        "points": 10,
        "secret": "VulnWorld{4dm1n_3ndp01nt_3262026}",
    },
    "menu_nosql": {
        "name": "NoSQL Menu",
        "points": 10,
        "secret": "VulnWorld{n0sql_1nj3ct_m3nu_3262026}",
    },
    "account_source": {
        "name": "Account page source",
        "points": 10,
        "secret": "VulnWorld{v13w_s0urc3_4cc0unt_3262026}",
    },
    "instagram_osint": {
        "name": "Instagram OSINT",
        "points": 10,
        "secret": "VulnWorld{1nst4gr4m_0s1nt_3262026}",
    },
}

ADMIN_ACCOUNT_USERNAME = "admin"
ADMIN_ACCOUNT_REWARD_FLAG = "VulnWorld{4dm1n_4cc0unt_d4shb04rd_3262026}"


def _migrate_flag_points() -> None:
    """Keep historical flag solve point values aligned with current config."""
    for flag_id, meta in CTF_FLAGS.items():
        try:
            flag_solves.update_many(
                {"flag_id": flag_id, "points": {"$ne": int(meta["points"])}},
                {"$set": {"points": int(meta["points"])}},
            )
        except Exception:
            # Avoid breaking app startup if DB is temporarily unavailable.
            pass


_migrate_flag_points()


def _seed_food_menu() -> None:
    """Ensure CTF menu rows exist in MongoDB (food collection)."""
    try:
        collection.update_one(
            {"ctf_menu_seed": "menu_nosql"},
            {
                "$set": {
                    "name": "Off-menu exploit platter",
                    "price": 999999.0,
                    "ctf_menu_seed": "menu_nosql",
                }
            },
            upsert=True,
        )
    except Exception:
        pass


_seed_food_menu()


def _ctf_user_points(username: str) -> int:
    total = 0
    for doc in flag_solves.find({"username": username}):
        total += int(doc.get("points", 0))
    return total


def _ctf_solved_flag_ids(username: str) -> set:
    return {d["flag_id"] for d in flag_solves.find({"username": username}, {"flag_id": 1})}


def _verify_stored_password(stored: str, password: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2:") or stored.startswith("scrypt:"):
        return check_password_hash(stored, password)
    return stored == password


@app.route('/account', methods=['GET'])
def account():
    """Sign up, log in, or view profile when authenticated."""
    member_since = None
    username = session.get("username")
    ctf_points = 0
    test_flag_solved = False
    admin_endpoint_flag_solved = False
    menu_nosql_flag_solved = False
    account_source_flag_solved = False
    instagram_osint_flag_solved = False
    is_admin_account = False
    if username:
        doc = login_collection.find_one({"username": username})
        if doc and doc.get("created_at"):
            raw = doc["created_at"]
            if hasattr(raw, "strftime"):
                member_since = raw.strftime("%B %d, %Y")
            else:
                member_since = str(raw)
        ctf_points = _ctf_user_points(username)
        test_flag_solved = "test" in _ctf_solved_flag_ids(username)
        admin_endpoint_flag_solved = "admin_endpoint" in _ctf_solved_flag_ids(username)
        menu_nosql_flag_solved = "menu_nosql" in _ctf_solved_flag_ids(username)
        account_source_flag_solved = "account_source" in _ctf_solved_flag_ids(username)
        instagram_osint_flag_solved = "instagram_osint" in _ctf_solved_flag_ids(username)
        is_admin_account = username.lower() == ADMIN_ACCOUNT_USERNAME
    return render_template(
        "account.html",
        member_since=member_since,
        ctf_points=ctf_points,
        test_flag_label=CTF_FLAGS["test"]["name"],
        test_flag_solved=test_flag_solved,
        admin_endpoint_flag_solved=admin_endpoint_flag_solved,
        menu_nosql_flag_solved=menu_nosql_flag_solved,
        account_source_flag_label=CTF_FLAGS["account_source"]["name"],
        account_source_flag_secret=CTF_FLAGS["account_source"]["secret"],
        account_source_flag_solved=account_source_flag_solved,
        instagram_osint_flag_label=CTF_FLAGS["instagram_osint"]["name"],
        instagram_osint_flag_solved=instagram_osint_flag_solved,
        is_admin_account=is_admin_account,
        admin_account_reward_flag=ADMIN_ACCOUNT_REWARD_FLAG,
    )


@app.route('/account/register', methods=['POST'])
def account_register():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not USERNAME_PATTERN.match(username):
        flash("Username must be 2–64 characters (letters, numbers, _, -, .).", "error")
        return redirect(url_for("account"))

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("account"))

    if login_collection.find_one({"username": username}):
        flash("That username is already taken.", "error")
        return redirect(url_for("account"))

    login_collection.insert_one(
        {
            "username": username,
            "password": generate_password_hash(password),
            "created_at": datetime.now(timezone.utc),
        }
    )
    session["username"] = username
    flash("Account created. You're signed in.", "success")
    return redirect(url_for("account"))


@app.route('/account/login', methods=['POST'])
def account_login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("Enter both username and password.", "error")
        return redirect(url_for("account"))

    doc = login_collection.find_one({"username": username})
    if not doc or not _verify_stored_password(doc.get("password", ""), password):
        flash("Invalid username or password.", "error")
        return redirect(url_for("account"))

    session["username"] = username
    flash("Signed in successfully.", "success")
    return redirect(url_for("account"))


@app.route('/account/logout', methods=['POST'])
def account_logout():
    session.pop("username", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("account"))


@app.route('/account/flag', methods=['POST'])
def account_submit_flag():
    username = session.get("username")
    if not username:
        flash("Log in to submit flags.", "error")
        return redirect(url_for("account"))

    submitted = (request.form.get("flag") or "").strip()
    if not submitted:
        flash("Enter a flag before submitting.", "error")
        return redirect(url_for("account"))

    solved_ids = _ctf_solved_flag_ids(username)
    matched_flag_id = None
    matched_meta = None
    for flag_id, meta in CTF_FLAGS.items():
        if submitted == meta["secret"]:
            matched_flag_id = flag_id
            matched_meta = meta
            break

    if not matched_flag_id or not matched_meta:
        flash("Incorrect flag. Keep hunting!", "error")
        return redirect(url_for("account"))

    if matched_flag_id in solved_ids:
        flash(f'You already solved "{matched_meta["name"]}".', "error")
        return redirect(url_for("account"))

    points = int(matched_meta["points"])
    try:
        flag_solves.insert_one(
            {
                "username": username,
                "flag_id": matched_flag_id,
                "flag_name": matched_meta["name"],
                "points": points,
                "solved_at": datetime.now(timezone.utc),
            }
        )
    except DuplicateKeyError:
        flash(f'You already solved "{matched_meta["name"]}".', "error")
        return redirect(url_for("account"))

    flash(f'Correct! "{matched_meta["name"]}" solved for +{points} points.', "success")
    return redirect(url_for("account"))

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
#   /admin      → admin panel (not linked from public nav)
#   /account    → sign up, log in, profile (MongoDB collections `login`, `flag_solves`)
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


@app.route('/admin')
def admin():
    """Internal-style admin panel (not listed on welcome page)."""
    return render_template('admin.html')


@app.route('/chat/message', methods=['POST'])
def chat_message():
    """Lightweight chat endpoint (no persistence)."""
    payload = request.get_json(silent=True) or {}
    user_message = str(payload.get("message", "")).strip()

    if not user_message:
        return jsonify({"reply": "Type a message so I can help."}), 400

    lowered = user_message.lower()
    if "menu" in lowered or "food" in lowered:
        reply = "Our menu search is on the Menu page. Enter a budget to see what you can grab."
    elif "event" in lowered:
        reply = "Special Events are listed on the Events page: Arcade Nights, LAN Parties, and Retro Consoles."
    elif "contact" in lowered or "phone" in lowered:
        reply = "You can find contact details on the Contact page, including email and phone."
    else:
        reply = f"You said: {user_message}"

    return jsonify({"reply": reply})


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

