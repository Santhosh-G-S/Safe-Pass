#app.py
import os
from flask import Flask, flash, redirect, render_template, url_for, jsonify, request, session
from datetime import datetime
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, auth, firestore

load_dotenv()

try:
    FIREBASE_CERT = os.getenv('FIREBASE_SERVICE_ACCOUNT', 'serviceAccountKey.json')
    cred = credentials.Certificate(FIREBASE_CERT)
    firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"Firebase initialization error: {e}")

# Initialize Firestore
db = firestore.client()

GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
MY_API_KEY = os.getenv("API_KEY")
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_AUTH_DOMAIN = os.getenv("FIREBASE_AUTH_DOMAIN", "safe-pass-c9c13.firebaseapp.com")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "safe-pass-c9c13")
if not MY_API_KEY:
    raise ValueError("API_KEY not found. Make sure it's set in your .env file.")
genai.configure(api_key=MY_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# ============= FIRESTORE HELPER FUNCTIONS =============

def get_user_by_email(email):
    """Get user document by email"""
    users_ref = db.collection('users')
    query = users_ref.where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()

    for doc in query:
        user_data = doc.to_dict()
        user_data['id'] = doc.id
        return user_data
    return None

def get_user_by_id(user_id):
    """Get user document by ID"""
    doc = db.collection('users').document(user_id).get()
    if doc.exists:
        user_data = doc.to_dict()
        user_data['id'] = doc.id
        return user_data
    return None

def create_user(email, password_hash):
    """Create new user in Firestore"""
    doc_ref = db.collection('users').add({
        'email': email,
        'hash': password_hash,
        'created_at': firestore.SERVER_TIMESTAMP
    })
    return doc_ref[1].id

def create_report(user_id, latitude, longitude, description, date, time, address, incident_type):
    """Create new report in Firestore"""
    doc_ref = db.collection('reports').add({
        'user_id': user_id,
        'latitude': float(latitude),
        'longitude': float(longitude),
        'description': description,
        'date': date,
        'time': time,
        'address': address,
        'incident_type': incident_type,
        'created_at': firestore.SERVER_TIMESTAMP
    })
    return doc_ref[1].id

def get_all_reports():
    """Get all reports from Firestore"""
    reports_ref = db.collection('reports').order_by('created_at', direction=firestore.Query.DESCENDING)
    reports = reports_ref.stream()

    result = []
    for doc in reports:
        report_data = doc.to_dict()
        report_data['id'] = doc.id

        # Convert Firestore timestamp to ISO string
        if 'created_at' in report_data and report_data['created_at']:
            report_data['created_at'] = report_data['created_at'].isoformat()

        result.append(report_data)

    return result

def get_reports_by_user(user_id):
    """Get reports for specific user"""
    reports_ref = db.collection('reports')
    query = reports_ref.where(filter=firestore.FieldFilter('user_id', '==', user_id))
    reports = query.stream()

    result = []
    for doc in reports:
        report_data = doc.to_dict()
        report_data['id'] = doc.id

        # Convert timestamp
        if 'created_at' in report_data and report_data['created_at']:
            report_data['created_at'] = report_data['created_at'].isoformat()

        result.append(report_data)

    # Sort in Python instead of Firestore
    result.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    return result

# ============= ROUTES =============

@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/check")
    return redirect("/login")

@app.route("/login", methods=["POST","GET"])
def login():
    session.clear()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not (email and password):
            flash("Please Enter valid email address and password","warning")
            return redirect(url_for('login'))

        user = get_user_by_email(email)

        if not user or not check_password_hash(user["hash"], password):
            flash("invalid email and/or password","warning")
            return redirect(url_for('login'))

        session["user_id"] = user["id"]
        return redirect("/check")

    else:
        return render_template("login.html", firebase_api_key=FIREBASE_API_KEY, firebase_auth_domain=FIREBASE_AUTH_DOMAIN, firebase_project_id=FIREBASE_PROJECT_ID)

@app.route("/report",methods=["POST","GET"])
def report():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("report.html", google_maps_key = GOOGLE_MAPS_API_KEY)

    else:
        lat = request.form.get('latitude')
        lng = request.form.get('longitude')
        address = request.form.get('address') or ''
        incident_type = request.form.get('incident_type') or ''
        description = request.form.get('description') or ''
        date = request.form.get('date') or ''
        time = request.form.get('time') or ''

        if not (lat and lng and description and date and time and incident_type):
            flash('Please fill all required fields and select a location', 'warning')
            return redirect(url_for('report'))

        try:
            create_report(
                session["user_id"],
                float(lat),
                float(lng),
                description.strip(),
                date,
                time,
                address,
                incident_type
            )
            flash('Report submitted successfully!', 'success')
        except Exception as e:
            flash(f'Error submitting report: {str(e)}', 'warning')
            print(f"Database error: {e}")

        return redirect(url_for('report'))


@app.route("/check")
def check():
    if "user_id" not in session:
        return redirect("/login")

    rows = get_all_reports()
    return render_template("check.html", row=rows, google_maps_key=GOOGLE_MAPS_API_KEY)


@app.route("/chatai",methods=["POST","GET"])
def chatai():
    if request.method == "GET":
        return render_template("chatai.html")

    try:
        data = request.get_json(silent=True) or request.form
        user_prompt = data.get("user_input", "")

        if not user_prompt:
            return jsonify({"error": "Empty prompt"}), 400

        system_prompt = """You are a Safety & Travel Advisory Assistant for Safe Pass, a community safety platform.

CORE RESPONSIBILITIES:
- Provide location-specific safety advice based on the user's situation
- Help assess safety risks for specific areas, times, and circumstances
- Offer practical safety recommendations for travelers
- Guide users on reporting incidents when needed
- Provide emergency contacts ONLY when there's an active safety concern

RESPONSE GUIDELINES:
1. ANALYZE THE CONTEXT: Consider location, time, and user's situation
2. BE SPECIFIC: Give actionable advice relevant to their exact query
3. BE CONVERSATIONAL: Sound helpful and supportive, not robotic
4. PRIORITIZE SAFETY: If you detect potential danger, emphasize immediate safety steps

EXAMPLES:
- If user mentions late night travel → Advise on safe transport options, well-lit areas, staying alert
- If user asks about area safety → Provide insights about that specific location if known
- If user reports active threat → Immediately provide emergency contacts and safety steps
- If general question → Give practical travel safety tips

EMERGENCY CONTACTS (only provide when relevant):
- Women's Helpline: 1091, 181
- Police: 100
- Ambulance: 102

DO NOT:
- Give generic safety tips when specific advice is needed
- Provide emergency numbers unless there's a safety concern
- Ask for unnecessary personal details
- Make assumptions about danger without context

Remember: Your goal is to make users feel safer and more informed about their specific situation."""

        full_prompt = f"""{system_prompt}

User query: {user_prompt}

Provide a helpful, contextual response:"""
        response = model.generate_content(full_prompt)
        response_text = response.text
        return jsonify({"reply": response_text})

    except Exception as e:
        print("ChatAI error:", e)
        return jsonify({"error": "Server error"}), 500


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not(email and password and confirmation):
            flash("Please fill all required fields",'warning')
            return redirect(url_for("register"))

        elif not password == confirmation:
            flash("rentered password mismatch",'warning')
            return redirect(url_for("register"))

        # Check if user already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            flash("Email Already Exists", 'warning')
            return redirect(url_for("register"))

        hpass = generate_password_hash(request.form.get("password"), method='scrypt', salt_length=16)

        try:
            create_user(email, hpass)
            flash("Registration successful! Please log in.", 'success')
        except Exception as e:
            flash("Error during registration.", 'danger')
            print(f"Registration error: {e}")

        return redirect("/login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/myreport")
def myreport():
    if "user_id" not in session:
        return redirect("/login")

    rows = get_reports_by_user(session["user_id"])
    return render_template("check.html", row=rows, google_maps_key=GOOGLE_MAPS_API_KEY)

@app.route("/firebase-login", methods=["POST"])
def firebase_login():
    """Handle Firebase Google Authentication"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        if not id_token:
            return jsonify({"error": "No token provided"}), 400

        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        email = decoded_token.get('email')

        if not email:
            return jsonify({"error": "No email in token"}), 400

        # Check if user exists
        user = get_user_by_email(email)

        if not user:
            # Create new user
            user_id = create_user(email, f"firebase_{uid}")
            session["user_id"] = user_id
        else:
            session["user_id"] = user["id"]

        session["email"] = email

        return jsonify({
            "success": True,
            "redirect": "/check"
        }), 200

    except auth.InvalidIdTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        print(f"Firebase login error: {e}")
        return jsonify({"error": "Authentication failed"}), 500

if __name__ == '__main__':
    is_production = os.getenv('FLASK_ENV') == 'production'

    if is_production:
        print("WARNING: Running Flask development server in production mode!")
        print("Use Gunicorn instead: gunicorn app:app")

    app.run(
        debug=not is_production,  # Debug only in development
        host='0.0.0.0',  # Allow external connections
        port=int(os.environ.get('PORT', 8080))
    )
