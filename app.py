#app.py
import os
from flask import Flask, flash, redirect, render_template, url_for, jsonify, request, session
from datetime import datetime
from flask import Blueprint
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
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
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

# ============= RESPONSE HELPERS =============

def success_response(data, message="Success", status=200):
    return jsonify({
        "success": True,
        "data": data,
        "message": message
    }), status

def error_response(code, message, status=400, details=None):
    return jsonify({
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "details": details or {}
        }
    }), status

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

@api_v1.route("/auth/login", methods=["POST"])
def login():
    session.clear()
    data = request.get_json()

    if not data:
        return error_response("INVALID_REQUEST", "JSON body required", 400)

    email = data.get("email")
    password = data.get("password")

    if not (email and password):
        return error_response("MISSING_FIELDS", "Email and password required", 400)

    user = get_user_by_email(email)

    if not user or not check_password_hash(user["hash"], password):
        return error_response("INVALID_CREDENTIALS", "Invalid email and/or password", 401)

    session["user_id"] = user["id"]
    return success_response({"redirect": "/check"}, "Login successful")

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


@api_v1.route("/chat", methods=["POST"])
def chatai():
    try:
        data = request.get_json(silent=True)

        if not data:
            return error_response("INVALID_REQUEST", "JSON body required", 400)

        user_prompt = data.get("user_input", "")

        if not user_prompt:
            return error_response("EMPTY_PROMPT", "user_input is required", 400)

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

        full_prompt = f"""{system_prompt} User query: {user_prompt} Provide a helpful, contextual response:"""
        response = model.generate_content(full_prompt)

        return success_response({"reply": response.text}, "Chat response generated")

    except Exception as e:
        print("ChatAI error:", e)
        return error_response("CHAT_ERROR", "Server error", 500)


@api_v1.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return error_response("INVALID_REQUEST", "JSON body required", 400)

    email = data.get("email")
    password = data.get("password")
    confirmation = data.get("confirmation")

    if not (email and password and confirmation):
        return error_response("MISSING_FIELDS", "Please fill all required fields", 400)

    if password != confirmation:
        return error_response("PASSWORD_MISMATCH", "Passwords do not match", 400)

    existing_user = get_user_by_email(email)
    if existing_user:
        return error_response("EMAIL_EXISTS", "Email already exists", 409)

    try:
        hpass = generate_password_hash(password, method='scrypt', salt_length=16)
        create_user(email, hpass)
        return success_response({}, "Registration successful", 201)
    except Exception as e:
        return error_response("REGISTER_FAILED", "Error during registration", 500)

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

@api_v1.route("/auth/firebase-login", methods=["POST"])
def firebase_login():
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        if not id_token:
            return error_response("NO_TOKEN", "No token provided", 400)

        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        email = decoded_token.get('email')

        if not email:
            return error_response("NO_EMAIL", "No email in token", 400)

        user = get_user_by_email(email)

        if not user:
            user_id = create_user(email, f"firebase_{uid}")
            session["user_id"] = user_id
        else:
            session["user_id"] = user["id"]

        session["email"] = email

        return success_response(
            {"redirect": "/check"},
            "Authentication successful"
        )

    except auth.InvalidIdTokenError:
        return error_response("INVALID_TOKEN", "Invalid token", 401)
    except Exception as e:
        return error_response("AUTH_FAILED", "Authentication failed", 500)

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html", firebase_api_key=FIREBASE_API_KEY,
                           firebase_auth_domain=FIREBASE_AUTH_DOMAIN,
                           firebase_project_id=FIREBASE_PROJECT_ID)

@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

app.register_blueprint(api_v1)

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
