from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
import random
import time
import os
import smtplib
import datetime
import mysql.connector
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# =======================
# Database Configuration
# =======================
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "1234",  # Update with your MySQL password
    "database": "voting_system"
}

# Flask App Configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ========================
# OTP Storage
# ========================
OTP_STORAGE = {}
OTP_EXPIRY_TIME = 300  # OTP valid for 5 minutes


def init_db():
    conn = mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"]
    )
    cursor = conn.cursor()

    cursor.execute("CREATE DATABASE IF NOT EXISTS voting_system")
    conn.close()

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS voters (
        voter_id VARCHAR(50) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        secret_question TEXT,
        secret_answer TEXT,
        otp VARCHAR(6),                   
        otp_expiration DATETIME,  
        has_voted BOOLEAN DEFAULT FALSE
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        vote_id INT AUTO_INCREMENT PRIMARY KEY,
        voter_id VARCHAR(50),
        candidate VARCHAR(50),
        vote_hash TEXT NOT NULL,
        previous_hash TEXT
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS candidates (
        candidate_id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) UNIQUE NOT NULL
    )""")

    # Insert default candidates if not present
    cursor.execute("SELECT COUNT(*) FROM candidates")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO candidates (name) VALUES (%s)", [
            ('Candidate A',),
            ('Candidate B',),
            ('Candidate C',)
        ])

    conn.commit()
    conn.close()
    print("Database initialized.")
# ========================
# Password Validation
# ========================
def validate_password(password):
    if len(password) < 10:
        return False
    if (sum(1 for c in password if c.isupper()) < 1 or
        sum(1 for c in password if c.islower()) < 1 or
        sum(1 for c in password if c.isdigit()) < 1 or
        sum(1 for c in password if not c.isalnum()) < 1):
        return False
    return True

# ========================
# OTP Generation and Sending
# ========================
def generate_otp():
    return random.randint(100000, 999999)

def generate_and_store_otp(voter_id):
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=5)  # OTP valid for 5 minutes

    # Insert OTP into the database
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    query = """
    UPDATE voters
    SET otp = %s, otp_expiration = %s
    WHERE voter_id = %s
    """
    cursor.execute(query, (otp, expiration_time, voter_id))
    conn.commit()
    cursor.close()
    conn.close()
    OTP_STORAGE[voter_id] = (otp, time.time())

    return otp

# def request_otp(voter_id, email):
#     otp = generate_otp()
#     OTP_STORAGE[voter_id] = (otp, time.time())
#     send_otp(email, otp)

def validate_otp(user_id, submitted_otp):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    query = """
    SELECT otp, otp_expiration
    FROM voters
    WHERE voter_id = %s
    """
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        stored_otp, otp_expiration = result
        if submitted_otp == stored_otp and datetime.datetime.now() < otp_expiration:
            return True  # OTP is valid
    return False  # OTP is invalid or expired

# ========================
# Cryptographic Utilities
# ========================
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# ==============================
# Registration and Authentication
# ==============================

def register_voter(voter_id, password, email, secret_question, secret_answer):
    if not validate_password(password):
        raise ValueError("Password does not meet the 10.4 rule.")
    
    if not email:
        raise ValueError("Email is required.")
  
    private_key, public_key = generate_keys()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    try:
        cursor.execute("""
        INSERT INTO voters (voter_id, password_hash, email, public_key, secret_question, secret_answer)
        VALUES (%s, %s, %s, %s, %s, %s)
        """, (voter_id, password_hash, email, public_key_pem.decode(), secret_question, secret_answer))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        conn.close()

    return private_key



def authenticate_voter(voter_id, password):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM voters WHERE voter_id = %s", (voter_id,))
    voter = cursor.fetchone()

    conn.close()

    if voter and bcrypt.checkpw(password.encode(), voter["password_hash"].encode()):
        return True, voter["public_key"]
    return False, None


def get_candidates():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM candidates")
    candidates = [row[0] for row in cursor.fetchall()]
    conn.close()
    return candidates

# ==========================
# Hacker Simulation
# ==========================
def hacker_simulation(voter_id, stolen_private_key_pem, candidate):
    stolen_private_key = serialization.load_pem_private_key(
        stolen_private_key_pem.encode(),
        password=None
    )

    # Generate the signed message for the vote
    message = f"{voter_id}:{candidate}".encode()
    signature = sign_message(stolen_private_key, message)

    return message, signature

# ==========================
# Flask Routes
# ==========================
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "voter_id" in session:
        flash("You are already logged in!", "info")
        return redirect(url_for("home"))

    if request.method == "POST":
        voter_id = request.form["voter_id"]
        password = request.form["password"]
        email = request.form["email"]
        secret_question = request.form["secret_question"]
        secret_answer = request.form["secret_answer"]

        if not voter_id or not password or not secret_question or not secret_answer:
            flash("All fields are required!", "error")
            return redirect(url_for("register"))

        if not validate_password(password):
            flash("Password must meet the 10.4 rule: Minimum 10 characters, including uppercase, lowercase, numbers, and special characters.", "error")
            return redirect(url_for("register"))

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if the voter ID already exists
            cursor.execute("SELECT COUNT(*) AS count FROM voters WHERE voter_id = %s", (voter_id,))
            result = cursor.fetchone()
            if result["count"] > 0:
                flash("Voter ID already exists. Please choose a different ID.", "error")
                return redirect(url_for("register"))

            # Proceed with registration
            private_key = register_voter(voter_id, password, email, secret_question, secret_answer)
            private_key_pem = save_private_key(private_key)
            return render_template("registration_success.html", private_key=private_key_pem)
        except mysql.connector.Error as e:
            flash(f"Database error: {e}", "error")
        finally:
            conn.close()

    return render_template("register.html")


@app.route('/login', methods=['GET','POST'])
def login():
    if "voter_id" in session:
        flash("You are already logged in!", "info")
        return redirect(url_for("home"))

    if request.method == "POST":
        voter_id = request.form['voter_id']
        password = request.form['password']

        # Authenticate user
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM voters WHERE voter_id = %s" , (voter_id,))
        voter = cursor.fetchone()
        cursor.close()
        conn.close()

        if voter and bcrypt.checkpw(password.encode(), voter["password_hash"].encode()):
            # Generate and store OTP
            otp = generate_and_store_otp(voter_id)
            session["voter_id_temp"] = voter_id
            flash(f"OTP {otp} has been generated and stored in the database for demonstration purposes.", "info")
            return render_template('verify_otp.html', voter_id=voter_id)
        else:
            flash("Invalid credentials. Please try again.", "danger")
            return redirect('/login')
    return render_template("login.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    voter_id = session.get("voter_id_temp")
    if not voter_id:
        flash("Unauthorized access or session expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        input_otp = request.form["otp"]

        # Validate OTP from the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT otp, otp_expiration FROM voters WHERE voter_id = %s", (voter_id,))
        voter = cursor.fetchone()
        conn.close()

        if voter:
            stored_otp = voter["otp"]
            otp_expiration = voter["otp_expiration"]

            # Check if OTP is expired
            if otp_expiration and time.time() > otp_expiration.timestamp():
                flash("OTP expired. Please log in again.", "error")
                return redirect(url_for("login"))

            # Validate the input OTP
            if input_otp == stored_otp:
                # Clear the OTP in the database after successful validation
                conn = mysql.connector.connect(**DB_CONFIG)
                cursor = conn.cursor()
                cursor.execute("UPDATE voters SET otp = NULL, otp_expiration = NULL WHERE voter_id = %s", (voter_id,))
                conn.commit()
                conn.close()

                flash("OTP validated successfully.", "success")
                return redirect(url_for("validate_secret"))
        
        flash("Invalid OTP. Please try again.", "error")

    return render_template("verify_otp.html")

@app.route("/validate_secret", methods=["GET", "POST"])
def validate_secret():
    voter_id = session.get("voter_id_temp")
    if not voter_id:
        flash("Unauthorized access or session expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        secret_answer = request.form["secret_answer"]

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT secret_answer FROM voters WHERE voter_id = %s", (voter_id,))
        voter = cursor.fetchone()
        conn.close()

        if voter and secret_answer == voter["secret_answer"]:
            session["voter_id"] = voter_id
            session.pop("voter_id_temp", None)
            flash("Login successful!", "success")
            return redirect(url_for("home"))

        flash("Incorrect secret answer!", "error")
        return redirect(url_for("validate_secret"))

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT secret_question FROM voters WHERE voter_id = %s", (voter_id,))
    voter = cursor.fetchone()
    conn.close()

    if voter:
        return render_template("validate_secret.html", secret_question=voter["secret_question"])
    else:
        flash("No secret question found for this voter ID.", "error")
        return redirect(url_for("login"))

# @app.route("/validate_secret", methods=["GET", "POST"])
# def validate_secret():
#     voter_id = session.get("voter_id_temp")
#     if not voter_id:
#         flash("Unauthorized access or session expired.", "error")
#         return redirect(url_for("login"))

#     if request.method == "POST":
#         secret_answer = request.form["secret_answer"]

#         conn = mysql.connector.connect(**DB_CONFIG)
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("SELECT secret_answer FROM voters WHERE voter_id = %s", (voter_id,))
#         voter = cursor.fetchone()
#         conn.close()

#         if voter and secret_answer == voter["secret_answer"]:
#             session["voter_id"] = voter_id
#             session.pop("voter_id_temp", None)
#             flash("Login successful!", "success")
#             return redirect(url_for("home"))

#         flash("Incorrect secret answer!", "error")
#         return redirect(url_for("validate_secret"))

#     conn = mysql.connector.connect(**DB_CONFIG)
#     cursor = conn.cursor(dictionary=True)
#     cursor.execute("SELECT secret_question FROM voters WHERE voter_id = %s", (voter_id,))
#     voter = cursor.fetchone()
#     conn.close()

#     if voter:
#         return render_template("validate_secret.html", secret_question=voter["secret_question"])
#     else:
#         flash("No secret question found for this voter ID.", "error")
#         return redirect(url_for("login"))

@app.route("/request_otp", methods=["POST"])
def request_otp_route():
    voter_id = session.get("voter_id")
    if not voter_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email FROM voters WHERE voter_id = %s", (voter_id,))
    voter = cursor.fetchone()
    conn.close()

    if not voter:
        flash("Invalid voter ID.", "error")
        return redirect(url_for("login"))

    email = voter["email"]
    otp = generate_otp()
    OTP_STORAGE[voter_id] = (otp, time.time())
    send_otp(email, otp)
    flash("OTP has been sent to your email.", "success")
    return redirect(url_for("validate_otp"))

# @app.route("/verify_otp", methods=["GET", "POST"])
# def verify_otp():
#     if request.method == "POST":
#         input_otp = request.form["otp"]
#         if "otp" not in session or "voter_id_temp" not in session:
#             flash("Session expired. Please log in again.", "error")
#             return redirect(url_for("login"))

#         if input_otp == session["otp"]:
#             # OTP is correct, log in the user
#             session["voter_id"] = session["voter_id_temp"]
#             session.pop("otp", None)
#             session.pop("voter_id_temp", None)
#             flash("Login successful!", "success")
#             return redirect(url_for("home"))
#         else:
#             flash("Invalid OTP. Please try again.", "error")
#             return redirect(url_for("verify_otp"))

#     return render_template("verify_otp.html")


@app.route("/cast_vote", methods=["GET", "POST"])
def cast_vote():
    if "voter_id" not in session:
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    voter_id = session["voter_id"]
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Check if the voter has already voted
    cursor.execute("SELECT has_voted FROM voters WHERE voter_id = %s", (voter_id,))
    voter = cursor.fetchone()
    if voter and voter["has_voted"]:
        conn.close()
        flash("You have already voted!", "error")
        return redirect(url_for("home"))

    # Fetch candidates
    cursor.execute("SELECT name FROM candidates")
    candidates = [row["name"] for row in cursor.fetchall()]

    if request.method == "POST":
        candidate = request.form["candidate"]
        # Record vote
        cursor.execute("UPDATE voters SET has_voted = TRUE WHERE voter_id = %s", (voter_id,))
        cursor.execute("INSERT INTO votes (voter_id, candidate, vote_hash, previous_hash) VALUES (%s, %s, %s, %s)",
                       (voter_id, candidate, sha256(f"{voter_id}:{candidate}".encode()).hexdigest(), ""))
        conn.commit()
        conn.close()
        flash(f"Vote cast for {candidate}!", "success")
        return redirect(url_for("home"))

    conn.close()
    return render_template("cast_vote.html", candidates=candidates)
@app.route("/logout")
def logout():
    session.clear()  # Clear the session
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

@app.route("/hacker_simulation", methods=["GET", "POST"])
def hacker_route():
    if request.method == "POST":
        voter_id = request.form["voter_id"]
        stolen_private_key = request.form["stolen_private_key"]
        candidate = request.form["candidate"]

        try:
            stolen_private_key = serialization.load_pem_private_key(
                stolen_private_key.encode(),
                password=None
            )
            message, signature = hacker_simulation(voter_id, stolen_private_key, candidate)
            flash(f"Hacker successfully attempted to cast a vote for {candidate}.", "success")
            flash(f"Message: {message.decode()} | Signature: {signature.hex()}", "info")
        except Exception as e:
            flash(f"Hacker attempt failed: {e}", "error")

    return render_template("hacker_simulation.html")

@app.route("/results")
def results():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT candidate, COUNT(*) AS votes FROM votes GROUP BY candidate")
    results = cursor.fetchall()
    conn.close()
    return render_template("results.html", results=results)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
