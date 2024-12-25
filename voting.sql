-- Create the database if it does not exist
CREATE DATABASE IF NOT EXISTS voting_system;

-- Use the created database
USE voting_system;

-- Table for storing voter information
-- CREATE TABLE IF NOT EXISTS voters (
--     voter_id VARCHAR(50) PRIMARY KEY,          -- Unique identifier for each voter
--     email VARCHAR(255) NOT NULL,               -- Email address of the voter
--     password_hash TEXT NOT NULL,                -- Hashed password for authentication
--     public_key TEXT NOT NULL,                   -- Public key for cryptographic operations
--     secret_question TEXT,                       -- Secret question for additional security
--     secret_answer TEXT,                         -- Hashed secret answer for verification
--     has_voted BOOLEAN DEFAULT FALSE             -- Flag to indicate if the voter has voted
-- );
CREATE TABLE voters (
    voter_id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(255),
    password_hash TEXT,
    public_key TEXT,
    private_key TEXT,
    secret_question TEXT,
    secret_answer TEXT,
    otp VARCHAR(6),
    otp_expiration DATETIME,
    has_voted TINYINT(1) DEFAULT 0,
    failed_attempts INT DEFAULT 0,
    lock_until DATETIME
);
-- Table for storing votes
CREATE TABLE IF NOT EXISTS votes (
    vote_id INT AUTO_INCREMENT PRIMARY KEY,
    voter_id VARCHAR(50),
    candidate VARCHAR(50),
    vote_hash TEXT NOT NULL,  -- Hash of the vote for integrity
    previous_hash TEXT,       -- Hash of the previous vote for chaining
    signature TEXT,           -- Digital signature of the vote
    FOREIGN KEY (voter_id) REFERENCES voters(voter_id)
);

-- Table for storing candidates
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id INT AUTO_INCREMENT PRIMARY KEY, -- Unique identifier for each candidate
    name VARCHAR(100) UNIQUE NOT NULL            -- Name of the candidate
);

-- Insert default candidates if not present
INSERT INTO candidates (name) VALUES 
('Candidate A'),
('Candidate B'),
('Candidate C')
ON DUPLICATE KEY UPDATE candidate_id = candidate_id; -- Prevent duplicate entries

CREATE TABLE IF NOT EXISTS merkle_root (
    id INT PRIMARY KEY DEFAULT 1,
    root_hash TEXT NOT NULL
);
-- ALTER TABLE voters
-- ADD COLUMN failed_attempts INT DEFAULT 0,
-- ADD COLUMN lock_until DATETIME DEFAULT NULL;

-- -- otp wala bhini he isme
