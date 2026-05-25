import { initializeApp } from "https://www.gstatic.com/firebasejs/12.6.0/firebase-app.js";
import { getAuth, GoogleAuthProvider, sendPasswordResetEmail, signInWithPopup } from "https://www.gstatic.com/firebasejs/12.6.0/firebase-auth.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/12.6.0/firebase-analytics.js";

// Read Firebase config from data attributes (set by Jinja in login.html)
const configEl = document.getElementById("firebase-config");

const firebaseConfig = {
    apiKey: configEl.dataset.apiKey,
    authDomain: configEl.dataset.authDomain,
    projectId: configEl.dataset.projectId,
    storageBucket: "safe-pass-c9c13.firebasestorage.app",
    messagingSenderId: "1046763012364",
    appId: "1:1046763012364:web:823ffd23219f10f8724929",
    measurementId: "G-S741HHK092"
};

const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app);
auth.languageCode = 'en';
const provider = new GoogleAuthProvider();

// Forgot Password Handler
const reset = document.getElementById("reset");
reset.addEventListener("click", function(event) {
    event.preventDefault();

    const email = document.getElementById("floatingInput").value;

    if (!email) {
        alert("Please enter your email address first");
        return;
    }

    sendPasswordResetEmail(auth, email)
        .then(() => {
            alert("Password reset email sent! Check your inbox.");
        })
        .catch((error) => {
            if (error.code === 'auth/user-not-found') {
                alert("No account found with this email address");
            } else if (error.code === 'auth/invalid-email') {
                alert("Invalid email address");
            } else {
                alert("Error: " + error.message);
            }
            console.error("Password reset error:", error);
        });
});

// Google Login Handler
const googleLogin = document.getElementById("google-login-btn");
if (googleLogin) {
    googleLogin.addEventListener("click", async function() {
        try {
            const result = await signInWithPopup(auth, provider);
            const idToken = await result.user.getIdToken();

            const response = await fetch('/api/v1/auth/firebase-login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ idToken })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                window.location.href = data.data.redirect;
            } else {
                alert('Login failed: ' + (data.error || 'Unknown error'));
            }

        } catch (error) {
            console.error('Error during sign in:', error);
            if (error.code === 'auth/popup-closed-by-user') return;
            alert('Sign in failed: ' + error.message);
        }
    });
}

// Email/Password Login Handler
const loginForm = document.getElementById("login-form");
loginForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    const email = document.getElementById("floatingInput").value;
    const password = document.getElementById("floatingPassword").value;

    const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (response.ok && data.success) {
        window.location.href = data.data.redirect;
    } else {
        alert(data.error.message || 'Login failed');
    }
});
