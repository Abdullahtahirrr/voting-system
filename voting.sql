-- Create the database if it does not exist
CREATE DATABASE IF NOT EXISTS voting_system;

-- Use the created database
USE voting_system;

-- Table for storing voter information
CREATE TABLE IF NOT EXISTS voters (
    voter_id VARCHAR(50) PRIMARY KEY,          -- Unique identifier for each voter
    email VARCHAR(255) NOT NULL,               -- Email address of the voter
    password_hash TEXT NOT NULL,                -- Hashed password for authentication
    public_key TEXT NOT NULL,                   -- Public key for cryptographic operations
    secret_question TEXT,                       -- Secret question for additional security
    secret_answer TEXT,                         -- Hashed secret answer for verification
    has_voted BOOLEAN DEFAULT FALSE             -- Flag to indicate if the voter has voted
);

-- Table for storing votes
CREATE TABLE IF NOT EXISTS votes (
    vote_id INT AUTO_INCREMENT PRIMARY KEY,     -- Unique identifier for each vote
    voter_id VARCHAR(50),                       -- Foreign key referencing the voter
    candidate VARCHAR(50),                      -- Candidate for whom the vote is cast
    vote_hash TEXT NOT NULL,                    -- Hash of the vote for integrity
    previous_hash TEXT,                         -- Hash of the previous vote for chaining
    FOREIGN KEY (voter_id) REFERENCES voters(voter_id) -- Establishing foreign key relationship
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