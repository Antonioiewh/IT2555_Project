-- Disable foreign key checks for a clean start (highly recommended when dropping and recreating related tables)
SET FOREIGN_KEY_CHECKS = 0;

-- Drop tables in reverse dependency order to avoid foreign key constraint issues
DROP TABLE IF EXISTS user_role_assignments;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS posts;         -- Assuming posts table exists and links to users
DROP TABLE IF EXISTS post_images;   -- Assuming post_images exists
DROP TABLE IF EXISTS post_likes;
DROP TABLE IF EXISTS events;        -- Assuming events exists
DROP TABLE IF EXISTS notifications; -- Assuming notifications exists
DROP TABLE IF EXISTS reports;       -- Assuming reports exists
DROP TABLE IF EXISTS messages;      -- Assuming messages exists
DROP TABLE IF EXISTS chat_participants; -- Assuming chat_participants exists
DROP TABLE IF EXISTS blocked_users; -- Assuming blocked_users exists
DROP TABLE IF EXISTS friend_chat_map; -- Assuming friend_chat_map exists
DROP TABLE IF EXISTS chats;         -- Assuming chats exists
DROP TABLE IF EXISTS user_public_keys; -- Assuming user_public_keys exists
DROP TABLE IF EXISTS chat_key_envelopes; -- Assuming chat_key_envelopes exists
DROP TABLE IF EXISTS friendships;   -- Assuming friendships exists
DROP TABLE IF EXISTS admin_actions; -- Assuming admin_actions exists
DROP TABLE IF EXISTS user_logs;     -- Assuming user_logs exists
DROP TABLE IF EXISTS knowledge_base_articles; -- Ticketing system tables
DROP TABLE IF EXISTS ticket_escalations;
DROP TABLE IF EXISTS ticket_assignments;
DROP TABLE IF EXISTS ticket_messages;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS ticket_categories;
DROP TABLE IF EXISTS support_agents;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS ModSecLog;
DROP TABLE IF EXISTS ErrorLog;
DROP TABLE IF EXISTS event_participants;

DROP TABLE IF EXISTS users; -- Drop users table last

-- **************************************
-- 1. User Accounts
-- **************************************
-- status is offline, online, suspended, terminated
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,

    phone_number VARCHAR(8) UNIQUE NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- Removed first_name VARCHAR(50) DEFAULT NULL,
    -- Removed last_name VARCHAR(50) DEFAULT NULL,
    profile_pic_url VARCHAR(255) DEFAULT NULL,
    banner_url VARCHAR(255) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    current_status ENUM('online', 'offline', 'suspended', 'terminated') NOT NULL DEFAULT 'offline',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_active_at DATETIME DEFAULT NULL,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    lockout_until DATETIME NULL,
    totp_secret VARCHAR(32)
);

-- **************************************
-- 2. Roles and Permissions (NEW/MODIFIED)
-- **************************************
CREATE TABLE roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT NULL
);

CREATE TABLE permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NULL
);

CREATE TABLE role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

CREATE TABLE user_role_assignments (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- **************************************
-- 3. Events/Reminders (Added for completeness, assuming they link to users)
-- **************************************
CREATE TABLE events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    event_datetime DATETIME NOT NULL,
    location VARCHAR(255) NULL,
    latitude FLOAT NULL,
    longitude FLOAT NULL,
    is_reminder BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Add this to your database_test.sql after the events table
CREATE TABLE event_participants (
    participation_id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    user_id INT NOT NULL,
    joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status ENUM('joined', 'left', 'cancelled') NOT NULL DEFAULT 'joined',
    UNIQUE KEY _event_user_uc (event_id, user_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- **************************************
-- 4. Posts (Added for completeness, assuming they link to users)
-- **************************************
CREATE TABLE posts (
    post_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    post_content TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE post_images (
    image_id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    order_index INT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE
);

CREATE TABLE post_likes (
    like_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_post_like (user_id, post_id)
);

-- Add indexes for better performance
CREATE INDEX idx_post_likes_user_id ON post_likes(user_id);
CREATE INDEX idx_post_likes_post_id ON post_likes(post_id);
CREATE INDEX idx_post_likes_created_at ON post_likes(created_at);
-- **************************************
-- 5. Notifications
-- **************************************
CREATE TABLE notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type VARCHAR(100) NOT NULL,
    source_id INT NULL, -- ID of the related item (e.g., post_id, friendship_id)
    message VARCHAR(255) NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- **************************************
-- 6. Customer Service
-- **************************************


CREATE TABLE reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    reporter_id INT NOT NULL,                    
    reported_user_id INT NOT NULL,

    report_type ENUM(
        'spam',
        'harassment',
        'impersonation',
        'inappropriate_content',
        'fraud',
        'other'
    ) NOT NULL,

    description TEXT NOT NULL,
    status ENUM('open', 'in_review', 'action_taken', 'rejected') NOT NULL DEFAULT 'open',
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    admin_notes TEXT NULL,

    FOREIGN KEY (reporter_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (reported_user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
-- **************************************
-- 7. Messaging
-- **************************************
CREATE TABLE chats (
    chat_id INT AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    -- chat_secret_key VARCHAR(64) NOT NULL
);

CREATE TABLE chat_participants (
    chat_participant_id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    user_id INT NOT NULL,
    cleared_at DATETIME NULL,
    is_in_chat BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (chat_id, user_id),
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE

);

CREATE TABLE friend_chat_map (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    friend_id INT NOT NULL,
    chat_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, friend_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE
);

CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    sender_id INT NOT NULL,
    message_text TEXT NOT NULL,
    sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted_by_sender BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted_by_receiver BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE blocked_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    blocker_id INT NOT NULL,
    blocked_id INT NOT NULL,
    chat_id INT NULL,
    reason VARCHAR(255) DEFAULT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at DATETIME NULL,
    UNIQUE KEY uq_blocker_blocked (blocker_id, blocked_id),
    INDEX idx_blocker (blocker_id),
    INDEX idx_blocked (blocked_id),
    FOREIGN KEY (blocker_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_public_keys (
  user_id INT NOT NULL PRIMARY KEY,
  alg VARCHAR(32) NOT NULL DEFAULT 'P-256',
  public_key_spki_b64 LONGTEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_upk_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE chat_key_envelopes (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  chat_id INT NOT NULL,
  user_id INT NOT NULL,
  key_version INT NOT NULL DEFAULT 1,
  envelope_b64 LONGTEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_chat_user_version (chat_id, user_id, key_version),
  CONSTRAINT fk_cke_chat FOREIGN KEY (chat_id) REFERENCES chats(chat_id),
  CONSTRAINT fk_cke_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);
-- **************************************
-- 8. Friend System
-- **************************************
CREATE TABLE friendships (
    friendship_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id1 INT NOT NULL,
    user_id2 INT NOT NULL,
    status ENUM('pending', 'accepted', 'blocked') NOT NULL DEFAULT 'pending',
    action_user_id INT NULL, -- User who initiated the last status change
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE (user_id1, user_id2), -- Ensures no duplicate friendship entries (enforce user_id1 < user_id2 in application logic)
    FOREIGN KEY (user_id1) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id2) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (action_user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- **************************************
-- 9. Admin Panel 3/4
-- **************************************
CREATE TABLE admin_actions (
    action_id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_user_id INT NULL,
    target_entity_type VARCHAR(50) NULL,
    target_entity_id INT NULL,
    details TEXT NULL,
    action_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (target_user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE user_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    log_type VARCHAR(100) NOT NULL,
    log_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE ModSecLog (
    id INT AUTO_INCREMENT PRIMARY KEY,          -- Unique identifier for each log entry
    date VARCHAR(20) NOT NULL,                  -- Date of the log (e.g., 12/Jun/2025)
    time VARCHAR(20) NOT NULL,                  -- Time of the log (e.g., 10:05:24)
    source VARCHAR(50) NOT NULL,                -- Source IP address (e.g., 172.18.0.1)
    request TEXT NOT NULL,                      -- Request details (e.g., GET /users_dashboard?search=username)
    response TEXT NOT NULL,                     -- Response details (e.g., HTTP/2.0 403)
    attack_detected TEXT NOT NULL               -- Attack type detected (e.g., XSS using libinjection)
);

CREATE TABLE ErrorLog (
    id INT AUTO_INCREMENT PRIMARY KEY,          -- Unique identifier for each log entry
    date VARCHAR(20) NOT NULL,                  -- Date of the log (e.g., 2025/06/01)
    time VARCHAR(20) NOT NULL,                  -- Time of the log (e.g., 12:40:46)
    level ENUM('notice', 'error', 'warning', 'critical') NOT NULL, -- Log level (e.g., notice, error)
    message TEXT NOT NULL,                      -- Log message (e.g., limiting requests, excess: 3.295 by zone "api_limit")
    client_ip VARCHAR(50) NOT NULL              -- Client IP address (e.g., 172.18.0.1)
);

CREATE TABLE webauthn_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key LONGBLOB NOT NULL,
    sign_count INT NOT NULL,
    nickname VARCHAR(100),
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- **************************************
-- 10. Ticketing System
-- **************************************

-- Support agents with clearance levels
CREATE TABLE support_agents (
    agent_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    clearance_level INT NOT NULL CHECK (clearance_level BETWEEN 1 AND 5),
    department VARCHAR(100) NOT NULL,
    specialization VARCHAR(255) NULL,
    created_by INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Ticket categories
CREATE TABLE ticket_categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NULL,
    default_priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL DEFAULT 'medium',
    required_clearance INT NOT NULL DEFAULT 1 CHECK (required_clearance BETWEEN 1 AND 5),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Support tickets
CREATE TABLE tickets (
    ticket_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category_id INT NOT NULL,
    priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL DEFAULT 'medium',
    status ENUM('open', 'in_progress', 'pending', 'resolved', 'closed', 'cancelled') NOT NULL DEFAULT 'open',
    resolution TEXT NULL,
    resolved_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES ticket_categories(category_id) ON DELETE RESTRICT
);

-- Ticket messages/replies
CREATE TABLE ticket_messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    is_internal BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Ticket assignments to agents
CREATE TABLE ticket_assignments (
    assignment_id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    agent_id INT NOT NULL,
    assigned_by INT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES support_agents(agent_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Ticket escalations
CREATE TABLE ticket_escalations (
    escalation_id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    escalated_by INT NOT NULL,
    escalated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    previous_priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL,
    new_priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE,
    FOREIGN KEY (escalated_by) REFERENCES support_agents(agent_id) ON DELETE CASCADE
);

-- Knowledge base articles
CREATE TABLE knowledge_base_articles (
    article_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    category_id INT NOT NULL,
    author_id INT NOT NULL,
    required_clearance INT NOT NULL DEFAULT 1 CHECK (required_clearance BETWEEN 1 AND 5),
    is_public BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES ticket_categories(category_id) ON DELETE RESTRICT,
    FOREIGN KEY (author_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Indexes for better performance
CREATE INDEX idx_tickets_user_id ON tickets(user_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_priority ON tickets(priority);
CREATE INDEX idx_tickets_created_at ON tickets(created_at);
CREATE INDEX idx_ticket_assignments_ticket_id ON ticket_assignments(ticket_id);
CREATE INDEX idx_ticket_assignments_agent_id ON ticket_assignments(agent_id);
CREATE INDEX idx_ticket_messages_ticket_id ON ticket_messages(ticket_id);
CREATE INDEX idx_support_agents_user_id ON support_agents(user_id);
CREATE INDEX idx_support_agents_clearance_level ON support_agents(clearance_level);

-- Enable foreign key checks again
SET FOREIGN_KEY_CHECKS = 1;

-- **************************************
-- Sample Data Insertion for Roles and Permissions
-- **************************************

-- Insert sample roles
INSERT INTO roles (role_name, description) VALUES
('admin', 'Has full administrative privileges over the system.'),
('user', 'Standard user with basic functionality like creating posts, events, sending messages.'),
('agent', 'Support agent with access to ticketing system and clearance-based ticket management.'),
('guest', 'Can view public content but cannot interact or create.');

-- Insert sample permissions
INSERT INTO permissions (permission_name, description) VALUES
('manage_users', 'Ability to create, update, and delete user accounts.'),
('delete_any_post', 'Ability to delete any post in the system.'),
('edit_any_post', 'Ability to edit any post in the system.'),
('create_post', 'Ability to create new posts.'),
('create_event', 'Ability to create new events/reminders.'),
('send_message', 'Ability to send private messages.'),
('view_admin_panel', 'Ability to access the administrative dashboard.'),
('resolve_reports', 'Ability to change the status of user-submitted reports.'),
('access_ticketing_dashboard', 'Ability to access support ticketing dashboard.'),
('manage_tickets', 'Ability to assign, escalate, and close tickets.'),
('view_all_tickets', 'Ability to view tickets based on clearance level.'),
('escalate_tickets', 'Ability to escalate ticket priority levels.'),
('assign_tickets', 'Ability to assign tickets to other agents.'),
('view_internal_notes', 'Ability to view internal agent notes on tickets.');

-- Assign permissions to roles
-- Admin Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'admin' AND p.permission_name IN (
    'manage_users', 'delete_any_post', 'edit_any_post', 'create_post',
    'create_event', 'send_message', 'view_admin_panel', 'resolve_reports',
    'access_ticketing_dashboard', 'manage_tickets', 'view_all_tickets',
    'escalate_tickets', 'assign_tickets', 'view_internal_notes'
);

-- Agent Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'agent' AND p.permission_name IN (
    'access_ticketing_dashboard', 'manage_tickets', 'view_all_tickets',
    'escalate_tickets', 'assign_tickets', 'view_internal_notes', 'create_post',
    'create_event', 'send_message'
);

-- User Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'user' AND p.permission_name IN (
    'create_post', 'create_event', 'send_message'
);

-- Guest Role Permissions (empty, as they typically only view public data, no direct interaction)

-- **************************************
-- Insert Sample Users and Assign Roles
-- **************************************
-- IMPORTANT: Replace YOUR_ADMIN_HASH_HERE, etc., with the actual hashes you generated!
-- For this example, I'll use placeholders for email, first_name, last_name.
-- In a real application, ensure each user has a unique email.
-- user|userpass , editor|editorpass, admin|adminpass
INSERT INTO users (username, phone_number, password_hash) VALUES
('admin', '12345679', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('user', '12345678', 'scrypt:32768:8:1$V460O7kVZYEBrWGC$d7a6bd9c8feced05b6d118ec8ef7d2c65c66d41171eb05c9589a49e60a95fda7d830ed98d7eb2e50830034bea978f6db05be620883bacb0bf4c5fc3a0e1d7b38'),
('user2', '11145671', 'scrypt:32768:8:1$xdPsxX7EC8sCphaO$f1b46069ede337b2b1f594c10680a3f85ab5906faa04af144994218cfa039e75a9aacf64e19b928be1661a5a1e53c5987f935131c1b8bbaece6b266c1a553160'),
('user3', '12345656', 'scrypt:32768:8:1$xdPsxX7EC8sCphaO$f1b46069ede337b2b1f594c10680a3f85ab5906faa04af144994218cfa039e75a9aacf64e19b928be1661a5a1e53c5987f935131c1b8bbaece6b266c1a553160'),
('user4', '11141671', 'scrypt:32768:8:1$xdPsxX7EC8sCphaO$f1b46069ede337b2b1f594c10680a3f85ab5906faa04af144994218cfa039e75a9aacf64e19b928be1661a5a1e53c5987f935131c1b8bbaece6b266c1a553160');

-- **************************************
-- Additional Support Agent User Accounts  
-- **************************************

-- Insert 5 new users for support agents
-- Passwords: support1pass, support2pass, support3pass, support4pass, support5pass
INSERT INTO users (username, phone_number, password_hash) VALUES
('support_l1_agent', '98765421', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_l2_tech', '98765422', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_l3_senior', '98765423', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_l4_critical', '98765424', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_l5_security', '98765425', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b');

-- Create orchestrator MySQL user for database management
CREATE USER IF NOT EXISTS 'orchestrator'@'%' IDENTIFIED BY 'orchestrator_password';
GRANT SUPER, PROCESS, REPLICATION SLAVE, REPLICATION CLIENT, RELOAD ON *.* TO 'orchestrator'@'%';
GRANT SELECT ON mysql.slave_master_info TO 'orchestrator'@'%';
GRANT SELECT ON performance_schema.replication_group_members TO 'orchestrator'@'%';
GRANT SELECT ON performance_schema.replication_group_member_stats TO 'orchestrator'@'%';
GRANT SELECT ON performance_schema.global_variables TO 'orchestrator'@'%';
FLUSH PRIVILEGES;

-- Assign roles to the newly created users
-- Admin user gets both admin and user roles
INSERT INTO user_role_assignments (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE (u.username = 'admin' AND r.role_name IN ('user', 'admin'))
   OR (u.username IN ('user', 'user2', 'user3', 'user4') AND r.role_name = 'user');

-- Assign user and agent roles to the new support agent accounts
INSERT INTO user_role_assignments (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE u.username IN ('support_l1_agent', 'support_l2_tech', 'support_l3_senior', 'support_l4_critical', 'support_l5_security') 
AND r.role_name IN ('user', 'agent');

-- **************************************
-- Sample data for ticket categories
-- **************************************
INSERT INTO ticket_categories (name, description, default_priority, required_clearance) VALUES
('General Support', 'General questions and basic support', 'low', 1),
('Technical Issues', 'Technical problems and bugs', 'medium', 2),
('Account Issues', 'Login, password, and account problems', 'medium', 2),
('Billing Support', 'Payment and billing related issues', 'medium', 2),
('Feature Requests', 'New feature requests and suggestions', 'low', 1),
('Security Concerns', 'Security-related reports and concerns', 'security', 4),
('Critical System Issues', 'System outages and critical problems', 'critical', 3),
('Data Privacy', 'Data protection and privacy concerns', 'high', 3),
('API Support', 'Developer and API related questions', 'medium', 2),
('Emergency Support', 'Urgent emergency situations', 'critical', 4);

-- **************************************
-- Create Support Agents with Different Clearance Levels
-- **************************************

-- Create 5 new support agents with proper clearance levels
INSERT INTO support_agents (user_id, clearance_level, department, specialization, created_by) VALUES
-- L1 Agent - Basic Support
((SELECT user_id FROM users WHERE username = 'support_l1_agent'), 1, 'Customer Service', 'General Inquiries, Account Issues, Basic Troubleshooting', 1),

-- L2 Agent - Technical Support  
((SELECT user_id FROM users WHERE username = 'support_l2_tech'), 2, 'Technical Support', 'Software Issues, API Support, Integration Problems', 1),

-- L3 Agent - Senior Support
((SELECT user_id FROM users WHERE username = 'support_l3_senior'), 3, 'Senior Technical Support', 'Complex Technical Issues, System Administration, Advanced Troubleshooting', 1),

-- L4 Agent - Critical Issues
((SELECT user_id FROM users WHERE username = 'support_l4_critical'), 4, 'Critical Response Team', 'System Outages, Critical Bugs, Emergency Response, Infrastructure Issues', 1),

-- L5 Agent - Security Specialist
((SELECT user_id FROM users WHERE username = 'support_l5_security'), 5, 'Security Team', 'Security Incidents, Breach Response, Vulnerability Management, Compliance', 1);

-- **************************************
-- Create Sample Tickets for Testing
-- **************************************

-- Sample tickets to test the clearance-based access control
INSERT INTO tickets (user_id, title, description, category_id, priority, status) VALUES
((SELECT user_id FROM users WHERE username = 'user'), 'Password Reset Request', 'I forgot my password and cannot login to my account', 3, 'low', 'open'),
((SELECT user_id FROM users WHERE username = 'user2'), 'API Integration Issue', 'Having trouble with the REST API authentication', 9, 'medium', 'open'),
((SELECT user_id FROM users WHERE username = 'user3'), 'System Performance Problem', 'The application is running very slowly', 2, 'high', 'open'),
((SELECT user_id FROM users WHERE username = 'user4'), 'Database Connection Failure', 'Cannot connect to database - system down', 7, 'critical', 'open'),
((SELECT user_id FROM users WHERE username = 'user'), 'Suspicious Login Activity', 'Noticed unauthorized login attempts from unknown IP addresses', 6, 'security', 'open');

-- Commit changes (optional, usually auto-committed in MySQL)
-- COMMIT;