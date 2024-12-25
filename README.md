# E-Voting System

## Overview
This E-Voting system is designed to ensure the **integrity** and **authentication** of votes while maintaining robust security and usability. The system uses modern cryptographic techniques and includes mechanisms to log and demonstrate simulated attacks for educational purposes.

### Key Features:
- **Integrity Verification**:
  - Implemented **hash chains** and **Merkle trees** to verify the integrity of the votes.
- **Authentication Mechanisms**:
  - Utilizes **SHA-256** for secure hashing.
  - Employs **RSA** for generating and verifying digital signatures.
  - Provides **OTP (One-Time Password)** and a **Secret Question** as additional layers of voter verification.
- **Password Security**:
  - Passwords are securely hashed using **bcrypt** to protect against brute-force attacks.
- **Attack Simulations**:
  - Includes demonstrations of various attacks such as:
    - Brute force attacks with account lockout after multiple failed attempts.
    - Replay attacks prevented using hash chains.
    - SQL injection and privilege escalation prevention.
    - OTP-based attacks with expiration checks.
  - Logs all attack attempts for transparency and analysis.
- **Comprehensive Logging**:
  - All activities and simulated attacks are logged to a file for review and debugging.

## Technologies Used
### Backend
- **Flask**: Used as the backend framework for API development.
- **Python**: The core programming language for the application.

### Frontend
- **HTML/CSS**: Used for building the user interface.

### Database
- **MySQL**: Used to store voter and voting data securely.

## Cryptographic Techniques
- **SHA-256**: Used for hashing data such as votes and ensuring their integrity.
- **RSA**: Used for digital signatures, ensuring authenticity of data.
- **bcrypt**: Used for securely hashing passwords.
- **Hash Chains**: Used to prevent replay attacks by linking votes sequentially.
- **Merkle Trees**: Used to verify vote integrity efficiently.

## Security Features
1. **Multi-factor Authentication**:
   - OTP sent to registered email.
   - Secret question verification.
2. **Vote Integrity**:
   - Each vote is hashed and linked in a hash chain.
   - Merkle trees allow efficient verification of all votes in the database.
3. **Account Lockout**:
   - Accounts are locked temporarily after multiple failed login attempts to mitigate brute force attacks.
4. **Attack Prevention**:
   - SQL Injection prevention through parameterized queries.
   - Replay attack prevention with hash chains.
   - OTP expiration checks to prevent reuse.

## Attack Simulations
The system demonstrates the following attack scenarios for educational purposes:
- **Brute Force Attack**:
  - Logs failed attempts and locks the account after a threshold is reached.
- **Replay Attack**:
  - Demonstrates how hash chains prevent duplicate votes.
- **SQL Injection**:
  - Shows how parameterized queries mitigate injection attempts.
- **Privilege Escalation**:
  - Demonstrates attempts to escalate user roles and logs the results.

## Logs
- All actions and attack simulations are logged to a file (`attack_logs.txt`) for auditing purposes.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Abdullahtahirrr/voting-system/voting-system.git
   ```
2. Navigate to the project directory:
   ```bash
   cd voting-system
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up the MySQL database:
   - Create a database named `voting_system`.
   - Run the SQL scripts provided in the `database` folder to set up the tables.

5. Start the Flask server:
   ```bash
   python app.py
   ```
6. Open your browser and navigate to `http://localhost:5000`.

## Usage
- **Voting Process**:
  - Register as a voter with email, password, and secret question/answer.
  - Authenticate using OTP sent to your email.
  - Cast your vote securely.
- **Integrity Check**:
  - The system uses hash chains and Merkle trees to ensure that all votes are tamper-proof.
- **Attack Logs**:
  - Review `attack_logs.txt` to see logs of all simulated attack scenarios.

## Future Enhancements
- Implement blockchain for a decentralized voting process.
- Add role-based access control for better administration.
- Improve UI/UX for enhanced user experience.

---

### License
This project is licensed under the MIT License. See `LICENSE` for more details.

