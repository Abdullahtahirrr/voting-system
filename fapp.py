from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
import random
import os
import mysql.connector
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
from datetime import datetime,timedelta
import time

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

# ========================
# MerkleTree
# ========================

class MerkleTree:
    def __init__(self, leaves):
        self.leaves = leaves
        self.levels = []  # Initialize levels as a list
        self.build_tree()

    def build_tree(self):
        # Populate self.levels here
        self.levels.append(self.leaves)
        while len(self.levels[-1]) > 1:
            current_level = []
            for i in range(0, len(self.levels[-1]), 2):
                left = self.levels[-1][i]
                right = self.levels[-1][i+1] if i+1 < len(self.levels[-1]) else left
                current_level.append(self.hash_pair(left, right))
            self.levels.append(current_level)

    def hash_leaf(self, leaf):
        # Hash a single leaf node
        return hashlib.sha256(leaf.encode()).hexdigest()

    def hash_pair(self, left, right):
        # Hash a pair of values (left and right)
        return hashlib.sha256((left + right).encode()).hexdigest()

    def get_root(self):
        # Get the root hash of the Merkle Tree
        return self.levels[-1][0] if self.levels else None

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
        private_key TEXT NOT NULL,
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
        previous_hash TEXT,
        signature TEXT NOT NULL
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
# def generate_otp():
#     return random.randint(100000, 999999)

def generate_and_store_otp(voter_id):
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    expiration_time = datetime.now() + timedelta(minutes=5)

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
def get_private_key(voter_id):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    try:
        # Query to get the voter's private key
        cursor.execute("SELECT private_key FROM voters WHERE voter_id = %s", (voter_id,))
        result = cursor.fetchone()

        if result:
            # Load the private key from PEM format
            private_key_pem = result["private_key"].encode()  # Ensure it's in bytes
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None  # Assuming the private key is not encrypted; handle securely in production
            )
            return private_key
        else:
            raise ValueError("Private key not found for the given voter ID.")
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    except Exception as e:
        print(f"Error retrieving private key: {e}")
        return None
    finally:
        cursor.close()
        conn.close()
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
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Store without encryption for demo purposes
    )

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    try:
        cursor.execute(""" 
        INSERT INTO voters (voter_id, password_hash, email, public_key, private_key, secret_question, secret_answer)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (voter_id, password_hash, email, public_key_pem.decode(), private_key_pem.decode(), secret_question, secret_answer))
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
# def hacker_simulation(voter_id, stolen_private_key_pem, candidate):
#     stolen_private_key = serialization.load_pem_private_key(
#         stolen_private_key_pem.encode(),
#         password=None
#     )

#     # Generate the signed message for the vote
#     message = f"{voter_id}:{candidate}".encode()
#     signature = sign_message(stolen_private_key, message)

#     return message, signature

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


# from datetime import datetime, timedelta

def verify_password(plain_password, hashed_password):
    # Compare the plain password with the hashed password
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if "voter_id" in session:
        flash("You are already logged in!", "info")
        return redirect(url_for("home"))
    if request.method == "POST":
        voter_id = request.form["voter_id"]
        password = request.form["password"]

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Fetch voter details
        cursor.execute("SELECT * FROM voters WHERE voter_id = %s", (voter_id,))
        voter = cursor.fetchone()

        if not voter:
            flash("Voter ID not found!", "error")
            conn.close()
            return redirect(url_for("login"))

        # Check if the account is locked
        if voter["lock_until"] and voter["lock_until"] > datetime.now():
            lock_remaining = voter["lock_until"] - datetime.now()
            flash(f"Account locked! Try again in {lock_remaining.seconds // 60} minutes.", "error")
            conn.close()
            return redirect(url_for("login"))

        # Verify the password
        if not verify_password(password, voter["password_hash"]):  
            failed_attempts = voter["failed_attempts"] + 1

            # Lock the account if failed attempts reach 3
            if failed_attempts >= 3:
                lock_until = datetime.now() + timedelta(minutes=5)
                cursor.execute(
                    "UPDATE voters SET failed_attempts = %s, lock_until = %s WHERE voter_id = %s",
                    (failed_attempts, lock_until, voter_id)
                )
                conn.commit()
                flash("Account locked due to too many failed attempts. Try again in 5 minutes.", "error")
            else:
                cursor.execute(
                    "UPDATE voters SET failed_attempts = %s WHERE voter_id = %s",
                    (failed_attempts, voter_id)
                )
                conn.commit()
                flash(f"Incorrect password! {3 - failed_attempts} attempts remaining.", "error")
            conn.close()
            return redirect(url_for("login"))

        # Reset failed attempts and lock_until on successful login
        cursor.execute(
            "UPDATE voters SET failed_attempts = 0, lock_until = NULL WHERE voter_id = %s",
            (voter_id,)
        )
        conn.commit()
        

        # Generate and store OTP
        otp = generate_and_store_otp(voter_id)
        session["voter_id_temp"] = voter_id
        flash(f"OTP {otp} has been generated and stored in the database for demonstration purposes.", "info")
        return render_template('verify_otp.html', voter_id=voter_id)

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


def hash_vote(voter_id, candidate, previous_hash):
    content = f"{voter_id}:{candidate}:{previous_hash}".encode()
    return hashlib.sha256(content).hexdigest()

import logging

# Set up logging for integrity checks
logging.basicConfig(
    filename="integrity_checks.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

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

        # Fetch previous vote hash
        cursor.execute("SELECT vote_hash FROM votes ORDER BY vote_id DESC LIMIT 1")
        result = cursor.fetchone()
        previous_hash = result["vote_hash"] if result else "0" * 64

        # Create vote hash
        vote_hash = hash_vote(voter_id, candidate, previous_hash)

        # Sign the vote
        private_key = get_private_key(voter_id)  # Implement this function to retrieve the private key
        signature = sign_message(private_key, vote_hash.encode())

        # Insert the vote into the database
        cursor.execute(""" 
        INSERT INTO votes (voter_id, candidate, vote_hash, previous_hash, signature) 
        VALUES (%s, %s, %s, %s, %s)
        """, (voter_id, candidate, vote_hash, previous_hash, signature.hex()))

        # Update the voter's status to indicate they have voted
        cursor.execute("UPDATE voters SET has_voted = TRUE WHERE voter_id = %s", (voter_id,))
        conn.commit()

        # Create a Merkle Tree for all votes
        cursor.execute("SELECT vote_hash FROM votes")
        all_votes = [row["vote_hash"] for row in cursor.fetchall()]
        merkle_tree = MerkleTree(all_votes)
        root_hash = merkle_tree.get_root()

        # Store the root hash in a secure location or log it
        print(f"Current Merkle Root Hash: {root_hash}")

        # Integrity Check: Recompute vote hash and verify
        recomputed_vote_hash = hash_vote(voter_id, candidate, previous_hash)
        if vote_hash != recomputed_vote_hash:
            logging.error(f"Integrity failure: Expected {recomputed_vote_hash}, Found {vote_hash}")
            flash("Integrity check failed after casting your vote.", "error")
            conn.close()
            return redirect(url_for("home"))

        # Verify Merkle Tree Root
        cursor.execute("SELECT vote_hash FROM votes")
        all_votes_after = [row["vote_hash"] for row in cursor.fetchall()]
        merkle_tree_after = MerkleTree(all_votes_after)
        new_root_hash = merkle_tree_after.get_root()

        if new_root_hash != root_hash:
            logging.error(f"Merkle Tree integrity failure: Expected {root_hash}, Found {new_root_hash}")
            flash("Integrity check failed for the Merkle Tree.", "error")
            conn.close()
            return redirect(url_for("home"))

        logging.info(f"Vote integrity maintained for voter_id: {voter_id}")
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
