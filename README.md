# Safe Pass

**Safe Pass** is a community-driven safety platform that enables users to submit detailed, location-based reports about incidents like theft, harassment, hazards, and other concerns. All reports are visualized on an interactive map, and users can receive AI-powered safety guidance through an intelligent chatbot assistant.

[**View Live Demo**](https://safe-pass-1046763012364.us-central1.run.app/)

## Features

- **Interactive Map Reporting:** Submit detailed safety incident reports by clicking on an interactive map, using current GPS location, or searching for specific addresses.
- **Street View Verification:** Integrated Google Street View allows users to visually verify locations before reporting or traveling.
- **Real-time Incident Dashboard:** Visualize community reports on a live, clustered map, filterable by incident type or keywords.
- **AI Safety Assistant:** A built-in chatbot (powered by Google Gemini) provides personalized safety advice, travel tips, and emergency resources.
- **Secure Authentication:** Supports both traditional email/password registration and one-click Google Sign-In via Firebase.

## Project Demo

Here is a visual walkthrough of the application in action.

### Core Interface
<div align="center">
  <img src="images/Login.png" width="45%" alt="Login Page"/>
  <img src="images/Check.png" width="45%" alt="Check Reports"/>
</div>

### Reporting & AI Features
<div align="center">
  <img src="images/Report.png" width="45%" alt="Report Incident"/>
  <img src="images/Streetview.png" width="45%" alt="Streetview"/>
</div>

### AI Assistant
<div align="center">
  <img src="images/Ai%20chat.png" width="600px" alt="AI Chat Interface"/>
</div>

## Technology Stack

This project leverages a modern tech stack to ensure reliability and scalability.

| Component | Technology | Description |
|-----------|------------|-------------|
| **Frontend** | HTML5 / CSS3 | Structure and Styling |
| | Bootstrap | Responsive UI Framework & Components |
| | JavaScript | Interactive logic & DOM manipulation |
| | Google Maps API | Interactive mapping, markers, and clustering |
| **Backend** | Flask | Python Micro-framework for routing |
| | Jinja2 | Server-side template rendering |
| | Werkzeug | Password hashing (Scrypt) |
| **Database** | Firestore | NoSQL document database for reports |
| | Firebase Auth | User identity and Google Sign-In |
| **AI & APIs** | Google Gemini | Generative AI for the Safety Chatbot |
| | Geocoding API | Address resolution and reverse geocoding |
| | Places API | Location search and autocomplete |
| **DevOps** | Docker | Containerization |
| | Google Cloud Run | Serverless hosting environment |

## Installation

To run this project locally, follow these steps:

### 1. Clone the Repository
```bash
git clone [https://github.com/Santhosh-G-S/Safe-Pass-Webapplication-Project.git](https://github.com/Santhosh-G-S/Safe-Pass-Webapplication-Project.git)
cd Safe-Pass-Webapplication-Project

### 2. Set up Environment Variables
Create a .env file in the root directory and add your API keys:
```bash
GOOGLE_MAPS_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
FLASK_SECRET_KEY=your_secret_key

### 3. Install Dependencies
Create a .env file in the root directory and add your API keys:
```bash
pip install -r requirements.txt

### 4. Run the Application
Create a .env file in the root directory and add your API keys:
```bash
flask run