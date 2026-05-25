const registerForm = document.getElementById("register-form");

registerForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    const email = document.getElementById("exampleInputEmail1").value;
    const password = document.getElementById("password").value;
    const confirmation = document.getElementById("confirmation").value;

    const response = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, confirmation })
    });

    const data = await response.json();

    if (response.ok && data.success) {
        alert("Registration successful! Please log in.");
        window.location.href = '/login';
    } else {
        alert(data.error.message || 'Registration failed');
    }
});
