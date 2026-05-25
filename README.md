<div align="center">

<img src="https://github.com/Santhosh-G-S/Safe-Pass/raw/main/Images/Login.png" alt="Safe Pass Banner" width="100%"/>

# 🛡️ Safe Pass

### Community-Driven Safety Reporting Platform

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Online-22c55e?style=for-the-badge)](https://safe-pass-1046763012364.us-central1.run.app/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![GCP](https://img.shields.io/badge/Google_Cloud-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)](https://cloud.google.com)
[![Firebase](https://img.shields.io/badge/Firebase-FFCA28?style=for-the-badge&logo=firebase&logoColor=black)](https://firebase.google.com)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

</div>

---

## 📌 Overview

**Safe Pass** is a full-stack, cloud-native community safety platform where users can report real-world incidents — theft, harassment, hazards — pinpointed on an interactive map. Reports are visualized in real time with clustered markers, and an AI-powered chatbot provides instant safety guidance and emergency resources.

> Built and deployed on **Google Cloud Run** with a serverless architecture, it handled **500+ concurrent users** with a **99.9% authentication success rate** during stress testing.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🗺️ **Interactive Map Reporting** | Submit incident reports by clicking the map, using GPS, or searching addresses |
| 📍 **Real-Time Incident Dashboard** | Live clustered map filterable by incident type or keywords |
| 🏙️ **Street View Verification** | Visually confirm locations via Google Street View before reporting or traveling |
| 🤖 **AI Safety Chatbot** | Gemini-powered assistant for safety tips, travel advice, and emergency resources |
| 🔐 **Secure Authentication** | Email/password + Google Sign-In via Firebase with Scrypt password hashing |
| ☁️ **Cloud-Native Deployment** | Containerized with Docker, deployed serverlessly on Google Cloud Run |

---

## 📸 Screenshots

<table>
  <tr>
    <td align="center"><b>Login Page</b></td>
    <td align="center"><b>Incident Dashboard</b></td>
  </tr>
  <tr>
    <td><img src="https://github.com/Santhosh-G-S/Safe-Pass/raw/main/Images/Login.png" width="100%"/></td>
    <td><img src="https://github.com/Santhosh-G-S/Safe-Pass/raw/main/Images/Check.png" width="100%"/></td>
  </tr>
  <tr>
    <td align="center"><b>Report an Incident</b></td>
    <td align="center"><b>Street View Integration</b></td>
  </tr>
  <tr>
    <td><img src="https://github.com/Santhosh-G-S/Safe-Pass/raw/main/Images/Report.png" width="100%"/></td>
    <td><img src="https://github.com/Santhosh-G-S/Safe-Pass/raw/main/Images/Streetview.png" width="100%"/></td>
  </tr>
  <tr>
    <td align="center" colspan="2"><b>AI Safety Chatbot</b></td>
  </tr>
  <tr>
    <td colspan="2" align="center"><img src="https://github.com/Santhosh-G-S/Safe-Pass/raw/main/Images/Ai%20chat.png" width="50%"/></td>
  </tr>
</table>

---

## 🏗️ Architecture & Tech Stack

┌─────────────────────────────────────────────────────────┐
│                      CLIENT BROWSER                     │
│         HTML5 · CSS3 · Bootstrap · JavaScript           │
│          Google Maps API · MarkerClusterer              │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP Requests
┌────────────────────▼────────────────────────────────────┐
│                 FLASK BACKEND (Python)                  │
│           RESTful API · Jinja2 · Werkzeug               │
│                  Deployed on Cloud Run                  │
└──────┬─────────────────────┬───────────────────────┬───┘
       │                     │                       │
┌──────▼──────┐   ┌──────────▼────────┐   ┌─────────▼──────┐
│  Firestore  │   │  Firebase Auth    │   │  Gemini AI API │
│  (Reports)  │   │  (Users/Google    │   │  (Chatbot)     │
│             │   │   Sign-In)        │   │                │
└─────────────┘   └───────────────────┘   └────────────────┘

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, Bootstrap, JavaScript |
| **Maps & Location** | Google Maps API, MarkerClusterer, Street View API, Places API, Geocoding API |
| **Backend** | Python, Flask, Jinja2, Werkzeug (Scrypt hashing) |
| **Database** | Cloud Firestore (NoSQL) |
| **Authentication** | Firebase Auth (Email + Google Sign-In) |
| **AI** | Google Gemini API |
| **DevOps** | Docker, Google Cloud Run |

---

## ⚡ Performance Highlights

- 🚀 **40% reduction** in deployment overhead via Cloud Run serverless architecture
- ⏱️ **200–600ms** warm-instance page load times
- 🔐 **99.9% auth success rate** under stress test with 500+ concurrent users
- 🗺️ **30% geospatial rendering improvement** via MarkerClusterer — handles 100+ concurrent markers at sub-second latency

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- A Google Cloud project with Maps, Gemini, Geocoding, and Places APIs enabled
- Firebase project with Firestore and Authentication set up

### 1. Clone the Repository

```bash
git clone https://github.com/Santhosh-G-S/Safe-Pass.git
cd Safe-Pass
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the root directory:

```env
GOOGLE_MAPS_API_KEY=your_google_maps_key
GEMINI_API_KEY=your_gemini_key
FLASK_SECRET_KEY=your_flask_secret_key
```

Also place your Firebase service account JSON as `serviceAccountKey.json` in the root.

### 4. Run Locally

```bash
flask run
```

Open `http://localhost:5000` in your browser.

### 5. Run with Docker

```bash
docker build -t safe-pass .
docker run -p 8080:8080 safe-pass
```

---

## 🌐 Deployment (Google Cloud Run)

```bash
# Build and push Docker image
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/safe-pass

# Deploy to Cloud Run
gcloud run deploy safe-pass \
  --image gcr.io/YOUR_PROJECT_ID/safe-pass \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

---

## 📁 Project Structure

Safe-Pass/
├── app.py                  # Main Flask application & routes
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container configuration
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JS, assets
└── Images/                 # Screenshots for documentation
