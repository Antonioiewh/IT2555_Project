-- Disable foreign key checks for a clean start (optional, useful if dropping tables)
SET FOREIGN_KEY_CHECKS = 0;

-- Drop table if it already exists to ensure a clean slate on recreation
-- This is useful for development to easily reset the database
DROP TABLE IF EXISTS users;

-- Create the users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Increased size for password hashes
    roles VARCHAR(255) DEFAULT '' -- For comma-separated roles
);

-- Insert sample users with their roles and hashed passwords
-- IMPORTANT: Replace YOUR_ADMIN_HASH_HERE, etc., with the actual hashes you generated!
INSERT INTO users (username, password_hash, roles) VALUES
('admin', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b', 'user,editor,admin'),
('editor', 'scrypt:32768:8:1$MACB13gQmz07eh4r$70fe403cc30e93c0605e8c1b5ecf64c43698b421268327e7a18cba40a3e5c25093d399ddbf774653715e2decbf3605d917a749a450dc60790d4e12c3e42c588d', 'user,editor'),
('user', 'scrypt:32768:8:1$V460O7kVZYEBrWGC$d7a6bd9c8feced05b6d118ec8ef7d2c65c66d41171eb05c9589a49e60a95fda7d830ed98d7eb2e50830034bea978f6db05be620883bacb0bf4c5fc3a0e1d7b38', 'user');

-- Enable foreign key checks again (optional)
SET FOREIGN_KEY_CHECKS = 1;

-- Commit changes (optional, auto-committed by default in many contexts)
-- COMMIT;