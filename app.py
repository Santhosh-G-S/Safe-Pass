# app.py
import os
from flask import Flask, flash, redirect, render_template, url_for, jsonify, request, session
from datetime import datetime
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, auth, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

# Load environment variables (for local development)
load_dotenv()

# Initialize Firebase
try:
    # Try to get credentials from environment or file
    if os.getenv('FIREBASE_CREDENTIALS'):
        # For Cloud Run: credentials from environment variable
        import json
        cred_dict = json.loads(os.getenv('FIREBASE_CREDENTIALS'))
        cred = credentials.Certificate(cred_dict)
    else:
        # For local: credentials from file
        FIREBASE_CERT = os.getenv('FIREBASE_SERVICE_ACCOUNT', 'serviceAccountKey.json')
        cred = credentials.Certificate(FIREBASE_CERT)

    firebase_admin.initialize_app(cred)
    print("✅ Firebase initialized successfully")
except Exception as e:
    print(f"❌ Firebase initialization error: {e}")

# Initialize Firestore
db = firestore.client()

# Get API keys from environment
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
MY_API_KEY = os.getenv("API_KEY")

if not MY_API_KEY:
    print("⚠️  WARNING: API_KEY not found in environment variables")
else:
    genai.configure(api_key=MY_API_KEY)
    model = genai.GenerativeModel('gemini-2.0-flash')

# Initialize Flask app
app = Flask(__name__)

# Generate secure secret key
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable must be set")

# Configure session to use filesystem (with cachelib)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "null"
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "flask_session")
Session(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# ============= FIRESTORE HELPER FUNCTIONS =============
@app.route('/firebase-config')
def firebase_config():
    return jsonify({
        'apiKey': os.getenv('FIREBASE_API_KEY'),
        'authDomain': os.getenv('FIREBASE_AUTH_DOMAIN'),
        'projectId': os.getenv('FIREBASE_PROJECT_ID'),
        'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET'),
        'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
        'appId': os.getenv('FIREBASE_APP_ID'),
        'measurementId': os.getenv('FIREBASE_MEASUREMENT_ID')
    })


def get_user_by_email(email):
    """Get user document by email"""
    users_ref = db.collection('users')
    query = users_ref.where(filter=FieldFilter('email', '==', email)).limit(1).stream()

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
    reports_ref = db.collection('reports').order_by(
        'created_at', direction=firestore.Query.DESCENDING)
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
    query = reports_ref.where(filter=FieldFilter('user_id', '==', user_id)).order_by(
        'created_at', direction=firestore.Query.DESCENDING)
    reports = query.stream()

    result = []
    for doc in reports:
        report_data = doc.to_dict()
        report_data['id'] = doc.id

        # Convert timestamp
        if 'created_at' in report_data and report_data['created_at']:
            report_data['created_at'] = report_data['created_at'].isoformat()

        result.append(report_data)

    return result

# ============= ROUTES =============


@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/check")
    return redirect("/login")


@app.route("/health")
def health():
    """Health check endpoint for Cloud Run"""
    return jsonify({"status": "healthy", "service": "safe-pass"}), 200


@app.route("/login", methods=["POST", "GET"])
def login():
    session.clear()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not (email and password):
            flash("Please Enter valid email address and password", "warning")
            return redirect(url_for('login'))

        user = get_user_by_email(email)

        if not user or not check_password_hash(user["hash"], password):
            flash("invalid email and/or password", "warning")
            return redirect(url_for('login'))

        session["user_id"] = user["id"]
        return redirect("/check")

    else:
        return render_template("login.html")


@app.route("/report", methods=["POST", "GET"])
def report():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("report.html", google_maps_key=GOOGLE_MAPS_API_KEY)

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


@app.route("/chatai", methods=["POST", "GET"])
def chatai():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("chatai.html")

    try:
        data = request.get_json(silent=True) or request.form
        user_prompt = data.get("user_input", "")

        if not user_prompt:
            return jsonify({"error": "Empty prompt"}), 400

        system_prompt = "You are a Safety & Travel Advisory Assistant for a community safety platform. Your role is to help users stay safe while traveling and report incidents,YOUR RESPONSIBILITIES: Guide travelers about safety in their destination areas, Help users report incidents (theft, harassment, accidents, etc.) with proper details, Provide safety recommendations based on location and time, Ask relevant follow-up questions to gather incident details, Offer immediate safety advice when users report active threats, Just provide any emergency contacts for womens helpline in india, Don't ask any other information to user"
        full_prompt = f"""{system_prompt} User: {user_prompt}"""
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

        if not (email and password and confirmation):
            flash("Please fill all required fields", 'warning')
            return redirect(url_for("register"))

        elif not password == confirmation:
            flash("rentered password mismatch", 'warning')
            return redirect(url_for("register"))

        # Check if user already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            flash("Email Already Exists", 'warning')
            return redirect(url_for("register"))

        hpass = generate_password_hash(request.form.get(
            "password"), method='scrypt', salt_length=16)

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
    # Get port from environment (Cloud Run sets this)
    port = int(os.environ.get('PORT', 8080))

    print(f"🚀 Starting Safe Pass on port {port}")
    print(f"📍 Environment: {os.getenv('FLASK_ENV', 'development')}")

    app.run(
        debug=False,
        host='0.0.0.0',  # CRITICAL for Cloud Run
        port=port
    )
