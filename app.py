import bcrypt
import random
import time
import mysql.connector
from hashlib import sha256
from tkinter import Tk, Label, Button, Entry, messagebox
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

# Initialize database connection
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
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        vote_id INT AUTO_INCREMENT PRIMARY KEY,
        voter_id VARCHAR(50),
        candidate VARCHAR(50),
        vote_hash TEXT NOT NULL,
        previous_hash TEXT
    )""")

    conn.commit()
    conn.close()
    print("Database initialized.")

# ========================
# Cryptographic Utilities
# ========================
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def hash_vote(voter_id, candidate, previous_hash):
    content = f"{voter_id}:{candidate}:{previous_hash}".encode()
    return sha256(content).hexdigest()
def generate_otp():
    return random.randint(100000, 999999)

# OTP Validation
def validate_otp(voter_id, otp):
    if voter_id not in OTP_STORAGE:
        return False, "OTP not requested."

    stored_otp, timestamp = OTP_STORAGE[voter_id]
    
    # Check if OTP is expired
    if time.time() - timestamp > OTP_EXPIRY_TIME:
        del OTP_STORAGE[voter_id]
        return False, "OTP expired."

    # Check OTP value
    if otp == stored_otp:
        del OTP_STORAGE[voter_id]  # Clear OTP after successful validation
        return True, "OTP validated successfully."

    # Handle brute-force attempt
    OTP_ATTEMPTS[voter_id] = OTP_ATTEMPTS.get(voter_id, 0) + 1
    if OTP_ATTEMPTS[voter_id] > MAX_OTP_ATTEMPTS:
        return False, "Too many incorrect attempts. Account locked temporarily."

    return False, "Invalid OTP."
# ==============================
# Registration and Authentication
# ==============================
def register_voter(voter_id, password):
    private_key, public_key = generate_keys()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO voters (voter_id, password_hash, public_key) VALUES (%s, %s, %s)",
                       (voter_id, password_hash, public_key_pem.decode()))
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

def generate_otp():
    return random.randint(100000, 999999)

# =============================
# Casting and Verifying Votes
# =============================
def cast_vote(voter_id, candidate, private_key):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Fetch previous hash
    cursor.execute("SELECT vote_hash FROM votes ORDER BY vote_id DESC LIMIT 1")
    result = cursor.fetchone()
    previous_hash = result["vote_hash"] if result else "0" * 64

    vote_hash = hash_vote(voter_id, candidate, previous_hash)
    
    cursor.execute("""
    INSERT INTO votes (voter_id, candidate, vote_hash, previous_hash) 
    VALUES (%s, %s, %s, %s)
    """, (voter_id, candidate, vote_hash, previous_hash))

    conn.commit()
    conn.close()
    print(f"Vote for {candidate} cast successfully.")
    return vote_hash

def verify_votes():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM votes")
    votes = cursor.fetchall()
    
    previous_hash = "0" * 64
    for vote in votes:
        recalculated_hash = hash_vote(vote["voter_id"], vote["candidate"], previous_hash)
        if recalculated_hash != vote["vote_hash"]:
            print(f"Tampered vote detected: {vote}")
        previous_hash = vote["vote_hash"]

    conn.close()
# ==========================
# GUI Updates for OTP Handling
# ==========================
class VotingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Voting System")

        Label(root, text="Voter ID:").grid(row=0, column=0)
        self.voter_id_entry = Entry(root)
        self.voter_id_entry.grid(row=0, column=1)

        Label(root, text="Password:").grid(row=1, column=0)
        self.password_entry = Entry(root, show="*")
        self.password_entry.grid(row=1, column=1)

        self.otp_label = Label(root, text="OTP:")
        self.otp_entry = Entry(root)

        Button(root, text="Register", command=self.register).grid(row=2, column=0)
        Button(root, text="Login", command=self.login).grid(row=2, column=1)
        Button(root, text="Validate OTP", command=self.validate_otp_gui).grid(row=3, column=1)

    def register(self):
        voter_id = self.voter_id_entry.get()
        password = self.password_entry.get()
        register_voter(voter_id, password)
        messagebox.showinfo("Registration", "Voter registered successfully.")

    def login(self):
        voter_id = self.voter_id_entry.get()
        password = self.password_entry.get()
        is_authenticated, public_key = authenticate_voter(voter_id, password)
        if is_authenticated:
            otp = generate_otp()
            OTP_STORAGE[voter_id] = (otp, time.time())
            OTP_ATTEMPTS[voter_id] = 0  # Reset attempts
            print(f"OTP: {otp} (For demo purposes only)")  # Normally, send via secure channel
            messagebox.showinfo("Login", "Authenticated successfully. OTP has been sent.")
            self.otp_label.grid(row=4, column=0)
            self.otp_entry.grid(row=4, column=1)
        else:
            messagebox.showerror("Login", "Authentication failed.")

    def validate_otp_gui(self):
        voter_id = self.voter_id_entry.get()
        otp = int(self.otp_entry.get())
        valid, message = validate_otp(voter_id, otp)
        if valid:
            messagebox.showinfo("OTP Validation", message)
        else:
            messagebox.showerror("OTP Validation", message)

if __name__ == "__main__":
    init_db()
    root = Tk()
    app = VotingGUI(root)
    root.mainloop()
