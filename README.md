### [Safe Pass](https://safe-pass-1046763012364.us-central1.run.app/) 



Safe pass enables users to submit detailed, location-based reports about incidents like theft, harassment, hazards, and other concerns. All reports are visualized on an interactive map, and users can receive AI-powered safety guidance through an intelligent chatbot assistant


## Project Demo
Here are some screenshots of the application in action.
![Login page](images/Login.png)
![Check Reports](images/Check.png)
![Report Incident](images/Reportpng)
![Ai Chat](images/Ai chat.png)
![Streetview](images/Streetview.png)


### Feature



* **Interactive Map Reporting and street view:** Users can submit detailed safety incident reports by clicking on an interactive map, using their current location, or searching for an address and use street view to verification the location.
* **Real-time Incident Dashboard:** All community reports are visualized on a live, clustered map, which can be filtered by incident type or keywords.
* **AI Safety Assistant:** A built-in chatbot (powered by Google Gemini) provides users with personalized safety advice, travel tips, and emergency contact information.
* **Secure Authentication:** The platform supports both traditional email/password registration and a one-click Google Sign-In option via Firebase.







### Technology



**Frontend:**

* HTML5
* CSS3
* Bootstrap - UI Framework (grid, components) 
* JavaScript 
* Google Maps JS API - Interactive mapping, markers, geocoding 
* MarkerCluster      -  Map optimization for large data sets 
* Jinja2             - Server-side template rendering 





**Backend:**

* Flask         - Web framework and routing 
* Flask-Session - Server-side session management 
* Werkzeug      - Password hashing (Scrypt) 
* Gunicorn      - Production WSGI server 
* python-dotenv - Environment variable management





**Database \\\& Cloud Services:**

* Google Cloud Firestore  - NoSQL document database for user and report data
* Firebase Authentication - User identity and Google Sign-In 
* Firebase Admin SDK      - Secure backend operations 





**API's:**

* Google Gemini API    - AI chatbot assistant 
* Google Maps JS API   - Interactive map display 
* Google Places API    - Location search and autocomplete 
* Google Geocoding API - Address resolution (reverse geocoding)



**Hosting:**

* Google Cloud Run



