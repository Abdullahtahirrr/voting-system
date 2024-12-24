import os
import hashlib
import mysql.connector
from datetime import datetime,timedelta
import bcrypt
import time
import random
import string

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "1234",
    "database": "voting_system"
}

LOG_FILE = "attack_logs.txt"

# Utility function to log attack results
def log_attack(attack_name, description, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] ATTACK: {attack_name}\n")
        file.write(f"DESCRIPTION: {description}\n")
        file.write(f"RESULT: {result}\n\n")

# Merkle Tree Implementation
class MerkleTree:
    def __init__(self, leaves):
        self.leaves = [self.hash_leaf(leaf) for leaf in leaves]
        self.tree = self.build_tree(self.leaves)

    def hash_leaf(self, leaf):
        return hashlib.sha256(leaf.encode()).hexdigest()

    def build_tree(self, nodes):
        while len(nodes) > 1:
            temp_nodes = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                temp_nodes.append(self.hash_leaf(left + right))
            nodes = temp_nodes
        return nodes

    def get_root(self):
        return self.tree[0] if self.tree else None

# Tampering Detection Attack
def detect_vote_tampering(vote_id, tampered_candidate):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Fetch all votes to construct the Merkle Tree
    cursor.execute("SELECT vote_hash FROM votes ORDER BY vote_id")
    all_votes = [row["vote_hash"] for row in cursor.fetchall()]
    original_merkle_tree = MerkleTree(all_votes)
    original_root = original_merkle_tree.get_root()

    # Attempt to tamper with a vote
    try:
        cursor.execute("UPDATE votes SET candidate = %s WHERE vote_id = %s", (tampered_candidate, vote_id))
        conn.commit()

        # Recalculate the Merkle Root
        cursor.execute("SELECT vote_hash FROM votes ORDER BY vote_id")
        tampered_votes = [row["vote_hash"] for row in cursor.fetchall()]
        tampered_merkle_tree = MerkleTree(tampered_votes)
        tampered_root = tampered_merkle_tree.get_root()

        if original_root != tampered_root:
            log_attack(
                "Vote Tampering",
                f"Tampering detected for vote ID {vote_id}. Original Root: {original_root}, Tampered Root: {tampered_root}",
                "Failed - Tampering detected"
            )
        else:
            log_attack(
                "Vote Tampering",
                f"Tampering undetected for vote ID {vote_id}. Original Root: {original_root}, Tampered Root: {tampered_root}",
                "Success - Tampering undetected"
            )
    except Exception as e:
        log_attack("Vote Tampering", f"Error while tampering vote ID {vote_id}.", f"Error - {str(e)}")
    finally:
        conn.close()

def replay_attack_with_merkle(voter_id, candidate):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Fetch all votes and the last Merkle Root
    cursor.execute("SELECT vote_hash FROM votes ORDER BY vote_id")
    all_votes = [row["vote_hash"] for row in cursor.fetchall()]
    original_merkle_tree = MerkleTree(all_votes)
    original_root = original_merkle_tree.get_root()

    # Fetch the last vote hash
    previous_hash = all_votes[-1] if all_votes else "0" * 64

    # Try to cast a duplicate vote
    try:
        # Generate a fake vote hash
        fake_vote_hash = hashlib.sha256(f"{voter_id}{candidate}{previous_hash}".encode()).hexdigest()

        # Insert the fake vote into the database
        cursor.execute("""
        INSERT INTO votes (voter_id, candidate, vote_hash, previous_hash, signature)
        VALUES (%s, %s, %s, %s, %s)
        """, (voter_id, candidate, fake_vote_hash, previous_hash, "fake_signature"))
        conn.commit()

        # Recompute the Merkle Root
        cursor.execute("SELECT vote_hash FROM votes ORDER BY vote_id")
        tampered_votes = [row["vote_hash"] for row in cursor.fetchall()]
        tampered_merkle_tree = MerkleTree(tampered_votes)
        tampered_root = tampered_merkle_tree.get_root()

        # Compare Merkle Roots
        if original_root != tampered_root:
            log_attack(
                "Replay Attack",
                f"Duplicate vote detected for voter ID {voter_id}. Original Root: {original_root}, Tampered Root: {tampered_root}",
                "Failed - Replay attack detected"
            )
        else:
            log_attack(
                "Replay Attack",
                f"Duplicate vote undetected for voter ID {voter_id}. Original Root: {original_root}, Tampered Root: {tampered_root}",
                "Success - Replay attack went undetected"
            )
    except Exception as e:
        log_attack("Replay Attack", f"Error while attempting duplicate vote.", f"Error - {str(e)}")
    finally:
        conn.close()




def generate_random_passwords(n=5, length=8):
    """Generate a list of random passwords."""
    passwords = []
    for _ in range(n):
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        passwords.append(password)
    return passwords

def brute_force_attack_with_lock_check(target_user_id, max_attempts=5, lock_duration_minutes=5):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Fetch account details
    cursor.execute("SELECT failed_attempts, lock_until, password_hash FROM voters WHERE voter_id = %s", (target_user_id,))
    result = cursor.fetchone()

    if not result:
        log_attack("Brute Force", f"Target user ID {target_user_id} not found.", "Failed")
        conn.close()
        return

    failed_attempts = result["failed_attempts"]
    lock_until = result["lock_until"]
    actual_password = result["password_hash"]

    # Check if account is locked
    if lock_until and datetime.now() < lock_until:
        log_attack("Brute Force", f"Account for user ID {target_user_id} is locked until {lock_until}.", "Failed")
        conn.close()
        return

    # Generate random passwords and add the actual password to the list
    attempted_passwords = generate_random_passwords(n=5, length=8)
    attempted_passwords.append(actual_password)
    random.shuffle(attempted_passwords)  # Shuffle the list to simulate unpredictability

    success = False

    for attempt, password in enumerate(attempted_passwords, start=1):
        if failed_attempts >= max_attempts:
            lock_until = datetime.now() + timedelta(minutes=lock_duration_minutes)
            cursor.execute("UPDATE voters SET lock_until = %s WHERE voter_id = %s", (lock_until, target_user_id))
            conn.commit()
            log_attack(
                "Brute Force",
                f"Account locked for user ID {target_user_id} after {failed_attempts} failed attempts.",
                "Failed"
            )
            break

        if bcrypt.checkpw(password.encode('utf-8'), actual_password.encode('utf-8')):
            success = True
            cursor.execute("UPDATE voters SET failed_attempts = 0 WHERE voter_id = %s", (target_user_id,))
            conn.commit()
            log_attack(
                "Brute Force",
                f"Password found for user ID {target_user_id}: {password}.",
                f"Success in {failed_attempts + 1} attempts"
            )
            break

        failed_attempts += 1
        cursor.execute("UPDATE voters SET failed_attempts = %s WHERE voter_id = %s", (failed_attempts, target_user_id))
        conn.commit()
        time.sleep(0.5)  # Simulating delay per attempt

    if not success and failed_attempts < max_attempts:
        log_attack(
            "Brute Force",
            f"Password not found for user ID {target_user_id}.",
            f"Failed after {failed_attempts} attempts"
        )

    conn.close()


# def brute_force_attack_with_lock_check(target_user_id, max_attempts=5, lock_duration_minutes=5):
#     conn = mysql.connector.connect(**DB_CONFIG)
#     cursor = conn.cursor(dictionary=True)

#     # Fetch account details
#     cursor.execute("SELECT failed_attempts, lock_until, password_hash FROM voters WHERE voter_id = %s", (target_user_id,))
#     result = cursor.fetchone()

#     if not result:
#         log_attack("Brute Force", f"Target user ID {target_user_id} not found.", "Failed")
#         conn.close()
#         return

#     failed_attempts = result["failed_attempts"]
#     lock_until = result["lock_until"]
#     actual_password = result["password_hash"]

#     # Check if account is locked
#     if lock_until and datetime.now() < lock_until:
#         log_attack("Brute Force", f"Account for user ID {target_user_id} is locked until {lock_until}.", "Failed")
#         conn.close()
#         return

#     # Simulate password attempts
#     attempted_passwords = ["password123", "admin", "123456", "letmein", actual_password]
#     success = False

#     for attempt, password in enumerate(attempted_passwords, start=1):
#         if failed_attempts >= max_attempts:
#             lock_until = datetime.now() + timedelta(minutes=lock_duration_minutes)
#             cursor.execute("UPDATE voters SET lock_until = %s WHERE voter_id = %s", (lock_until, target_user_id))
#             conn.commit()
#             log_attack(
#                 "Brute Force",
#                 f"Account locked for user ID {target_user_id} after {failed_attempts} failed attempts.",
#                 "Failed"
#             )
#             break

#         if bcrypt.checkpw(password.encode('utf-8'), actual_password.encode('utf-8')):
#             success = True
#             cursor.execute("UPDATE voters SET failed_attempts = 0 WHERE voter_id = %s", (target_user_id,))
#             conn.commit()
#             log_attack(
#                 "Brute Force",
#                 f"Password found for user ID {target_user_id}: {password}.",
#                 f"Success in {failed_attempts + 1} attempts"
#             )
#             break

#         failed_attempts += 1
#         cursor.execute("UPDATE voters SET failed_attempts = %s WHERE voter_id = %s", (failed_attempts, target_user_id))
#         conn.commit()
#         time.sleep(0.5)  # Simulating delay per attempt

#     if not success and failed_attempts < max_attempts:
#         log_attack(
#             "Brute Force",
#             f"Password not found for user ID {target_user_id}.",
#             f"Failed after {failed_attempts} attempts"
#         )

#     conn.close()



def timed_otp_brute_force(voter_id, duration_in_seconds=120):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    otp = random.randint(100000, 999999)
    cursor.execute("UPDATE voters SET otp = %s WHERE voter_id = %s", (otp, voter_id))
    # Fetch the actual OTP for the voter
    cursor.execute("SELECT otp FROM voters WHERE voter_id = %s", (voter_id,))
    result = cursor.fetchone()

    if not result:
        log_attack("Timed OTP Brute Force", f"Target voter ID {voter_id} not found.", "Failed")
        conn.close()
        return

    actual_otp = result["otp"]
    start_time = time.time()
    attempts = 0
    success = False

    while time.time() - start_time < duration_in_seconds:
        guessed_otp = f"{attempts:06d}"  # Format to 6-digit OTP
        attempts += 1

        if guessed_otp == actual_otp:
            success = True
            log_attack(
                "Timed OTP Brute Force",
                f"Correct OTP guessed: {guessed_otp} for voter ID {voter_id} in {attempts} attempts.",
                "Success"
            )
            break

    if not success:
        log_attack(
            "Timed OTP Brute Force",
            f"Failed to guess OTP for voter ID {voter_id} after {attempts} attempts within {duration_in_seconds} seconds.",
            "Failed"
        )

    conn.close()

# Main Function to Run All Attacks
if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)  # Clear previous logs

    print("Starting attack simulations...\n")

    # Tampering detection using Merkle Root
    detect_vote_tampering(vote_id=1, tampered_candidate="Candidate A")

    # Replay attack simulation
    # replay_attack(voter_id=1, candidate="Candidate A")
    # sql_injection_attack()
    # brute_force_attack(target_user_id=1, max_attempts=4)
    # detect_vote_tampering(vote_id=1, candidate="Candidate A")
    replay_attack_with_merkle(voter_id=1, candidate="Candidate A")
    brute_force_attack_with_lock_check(target_user_id=1, max_attempts=4)
    timed_otp_brute_force(voter_id=1, duration_in_seconds=30)


    print(f"Attack simulations completed. Logs saved in '{LOG_FILE}'.")
