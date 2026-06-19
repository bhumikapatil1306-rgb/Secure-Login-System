from flask import Flask, request, session, redirect, url_for, render_template_string
import sqlite3
import bcrypt
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key"

# -----------------------------
# Database Setup
# -----------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password BLOB NOT NULL,
        twofa_secret TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# -----------------------------
# Home Page
# -----------------------------
@app.route("/")
def home():
    if "user" in session:
        return f"""
        <h2>Welcome {session['user']}</h2>
        <a href='/dashboard'>Dashboard</a><br>
        <a href='/logout'>Logout</a>
        """
    return """
    <h2>Secure Login System</h2>
    <a href='/register'>Register</a><br>
    <a href='/login'>Login</a>
    """

# -----------------------------
# Registration
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            return "Username must be at least 3 characters"

        if len(password) < 8:
            return "Password must be at least 8 characters"

        hashed = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        )

        secret = pyotp.random_base32()

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()

            # Parameterized query protects from SQL injection
            cursor.execute(
                "INSERT INTO users(username,password,twofa_secret) VALUES(?,?,?)",
                (username, hashed, secret)
            )

            conn.commit()
            conn.close()

            return """
            Registration successful.<br>
            <a href='/login'>Login Now</a>
            """

        except sqlite3.IntegrityError:
            return "Username already exists"

    return """
    <h2>Register</h2>
    <form method='post'>
        Username:<br>
        <input name='username'><br><br>

        Password:<br>
        <input type='password' name='password'><br><br>

        <button type='submit'>Register</button>
    </form>
    """

# -----------------------------
# Login
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password, twofa_secret FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if not user:
            return "Invalid username or password"

        stored_hash = user[0]
        secret = user[1]

        if bcrypt.checkpw(password.encode(), stored_hash):

            session["temp_user"] = username
            session["2fa_secret"] = secret

            return redirect(url_for("verify_2fa"))

        return "Invalid username or password"

    return """
    <h2>Login</h2>
    <form method='post'>
        Username:<br>
        <input name='username'><br><br>

        Password:<br>
        <input type='password' name='password'><br><br>

        <button type='submit'>Login</button>
    </form>
    """

# -----------------------------
# 2FA Setup & Verification
# -----------------------------
@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():

    if "temp_user" not in session:
        return redirect("/login")

    secret = session["2fa_secret"]

    if request.method == "POST":

        token = request.form["token"]

        if pyotp.TOTP(secret).verify(token):

            session["user"] = session["temp_user"]

            session.pop("temp_user", None)
            session.pop("2fa_secret", None)

            return redirect("/dashboard")

        return "Invalid OTP"

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=session["temp_user"],
        issuer_name="SecureLoginApp"
    )

    img = qrcode.make(totp_uri)

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")

    qr_code = base64.b64encode(
        buffer.getvalue()
    ).decode()

    return render_template_string("""
    <h2>Two-Factor Authentication</h2>

    <p>Scan QR with Google Authenticator:</p>

    <img src="data:image/png;base64,{{qr}}">

    <form method="post">
        OTP Code:<br>
        <input name="token"><br><br>

        <button type="submit">
            Verify
        </button>
    </form>
    """, qr=qr_code)

# -----------------------------
# Dashboard
# -----------------------------
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return f"""
    <h2>Dashboard</h2>
    Logged in as: {session['user']}<br><br>

    <a href='/logout'>Logout</a>
    """

# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():

    session.clear()

    return """
    Logged out successfully.<br>
    <a href='/'>Home</a>
    """

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
