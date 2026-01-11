-- =================================================================================
-- SOCIAL MEDIA & TICKETING SYSTEM DATABASE SCHEMA
-- =================================================================================
-- Author: Application Development Team
-- Purpose: Complete database schema for social media platform with ticketing system
-- Features: User management, posts, events, messaging, ticketing, role-based access, archive system
-- =================================================================================

-- =================================================================================
-- DATABASE INITIALIZATION
-- =================================================================================

-- Disable foreign key checks for clean database recreation
SET FOREIGN_KEY_CHECKS = 0;

-- =================================================================================
-- DROP TABLES (In Reverse Dependency Order)
-- =================================================================================

-- Drop junction/relationship tables first
DROP TABLE IF EXISTS user_role_assignments;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS ticket_assignments;
DROP TABLE IF EXISTS ticket_escalations;
DROP TABLE IF EXISTS ticket_messages;
DROP TABLE IF EXISTS chat_participants;
DROP TABLE IF EXISTS friend_chat_map;
DROP TABLE IF EXISTS event_participants;
DROP TABLE IF EXISTS post_images;
DROP TABLE IF EXISTS post_likes;
DROP TABLE IF EXISTS blocked_users;

-- Drop archive tables
DROP TABLE IF EXISTS terminated_tickets_audit;
DROP TABLE IF EXISTS archived_tickets;

-- Drop main content tables
DROP TABLE IF EXISTS knowledge_base_articles;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS ticket_categories;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS chats;
DROP TABLE IF EXISTS user_chat_locks;
DROP TABLE IF EXISTS friendships;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS admin_actions;
DROP TABLE IF EXISTS user_logs;
DROP TABLE IF EXISTS webauthn_credentials;

-- Drop support/reference tables
DROP TABLE IF EXISTS support_agents;
DROP TABLE IF EXISTS clearance_levels;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS ModSecLog;
DROP TABLE IF EXISTS ErrorLog;

-- Drop core table last
DROP TABLE IF EXISTS users;

-- =================================================================================
-- CORE SYSTEM TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Users Table - Core user accounts
-- ---------------------------------------------------------------------------------
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    phone_number VARCHAR(8) UNIQUE NULL,
    password_hash VARCHAR(255) NOT NULL,
    profile_pic_url VARCHAR(255) DEFAULT NULL,
    banner_url VARCHAR(255) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    current_status ENUM('online', 'offline', 'suspended', 'terminated') NOT NULL DEFAULT 'offline',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_active_at DATETIME DEFAULT NULL,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    lockout_until DATETIME NULL,
    totp_secret VARCHAR(32),
    -- Encryption Keys for Messaging ---
    public_key TEXT NULL,
    encrypted_private_key TEXT NULL,
    key_salt VARCHAR(64) NULL -- To derive key from password for private key encryption
);

-- ---------------------------------------------------------------------------------
-- Authentication & Security Tables
-- ---------------------------------------------------------------------------------
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

-- =================================================================================
-- ROLE-BASED ACCESS CONTROL (RBAC) SYSTEM
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Roles Table
-- ---------------------------------------------------------------------------------
CREATE TABLE roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT NULL
);

-- ---------------------------------------------------------------------------------
-- Permissions Table
-- ---------------------------------------------------------------------------------
CREATE TABLE permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NULL
);

-- ---------------------------------------------------------------------------------
-- Role-Permission Mapping
-- ---------------------------------------------------------------------------------
CREATE TABLE role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- User-Role Assignment
-- ---------------------------------------------------------------------------------
CREATE TABLE user_role_assignments (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- =================================================================================
-- TICKETING SYSTEM TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Clearance Levels for Security Classification
-- ---------------------------------------------------------------------------------
CREATE TABLE clearance_levels (
    level_id INT PRIMARY KEY,
    level_name VARCHAR(50) NOT NULL UNIQUE,
    level_description TEXT,
    can_view_public BOOLEAN DEFAULT TRUE,
    can_view_internal BOOLEAN DEFAULT FALSE,
    can_view_confidential BOOLEAN DEFAULT FALSE,
    can_view_secret BOOLEAN DEFAULT FALSE,
    can_view_top_secret BOOLEAN DEFAULT FALSE
);

-- ---------------------------------------------------------------------------------
-- Support Agents with Clearance Levels
-- ---------------------------------------------------------------------------------
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
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (clearance_level) REFERENCES clearance_levels(level_id) ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------------------
-- Ticket Categories
-- ---------------------------------------------------------------------------------
CREATE TABLE ticket_categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NULL,
    default_priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL DEFAULT 'medium',
    required_clearance INT NOT NULL DEFAULT 1 CHECK (required_clearance BETWEEN 1 AND 5),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------------
-- Support Tickets with Security Classification
-- ---------------------------------------------------------------------------------
CREATE TABLE tickets (
    ticket_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category_id INT NOT NULL,
    priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL DEFAULT 'medium',
    classification ENUM('public', 'internal', 'confidential', 'secret', 'top_secret') NOT NULL DEFAULT 'public',
    status ENUM('open', 'in_progress', 'pending', 'resolved', 'closed', 'cancelled') NOT NULL DEFAULT 'open',
    resolution TEXT NULL,
    resolved_at DATETIME NULL,
    archived_at DATETIME NULL,
    archived_by INT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES ticket_categories(category_id) ON DELETE RESTRICT,
    FOREIGN KEY (archived_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------------------
-- Archived Tickets - Read-only with clearance level restrictions
-- ---------------------------------------------------------------------------------
CREATE TABLE archived_tickets (
    archived_ticket_id INT AUTO_INCREMENT PRIMARY KEY,
    original_ticket_id INT NOT NULL,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category_id INT NULL,
    priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL,
    status VARCHAR(50) NOT NULL,
    classification ENUM('public', 'internal', 'confidential', 'secret', 'top_secret') NOT NULL,
    resolution TEXT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    resolved_at DATETIME NULL,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archived_by INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES ticket_categories(category_id) ON DELETE SET NULL,
    FOREIGN KEY (archived_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Terminated Tickets Audit Trail
-- ---------------------------------------------------------------------------------
CREATE TABLE terminated_tickets_audit (
    audit_id INT AUTO_INCREMENT PRIMARY KEY,
    original_ticket_id INT NOT NULL,
    ticket_data JSON NOT NULL,
    terminated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    terminated_by INT NOT NULL,
    reason TEXT NULL,
    FOREIGN KEY (terminated_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Ticket Messages & Communication
-- ---------------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------------
-- Ticket Assignment Management
-- ---------------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------------
-- Ticket Escalation Tracking
-- ---------------------------------------------------------------------------------
CREATE TABLE ticket_escalations (
    escalation_id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    escalated_by INT NOT NULL,
    escalated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    previous_priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL,
    new_priority ENUM('low', 'medium', 'high', 'critical', 'security') NOT NULL,
    previous_classification ENUM('public', 'internal', 'confidential', 'secret', 'top_secret') NULL,
    new_classification ENUM('public', 'internal', 'confidential', 'secret', 'top_secret') NULL,
    escalation_type ENUM('priority', 'tier') NOT NULL DEFAULT 'priority',
    reason TEXT NOT NULL,
    FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE,
    FOREIGN KEY (escalated_by) REFERENCES support_agents(agent_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Knowledge Base Articles
-- ---------------------------------------------------------------------------------
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

-- =================================================================================
-- SOCIAL MEDIA CONTENT TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Events & Reminders
-- ---------------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------------
-- Event Participation
-- ---------------------------------------------------------------------------------
CREATE TABLE event_participants (
    participation_id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    user_id INT NOT NULL,
    joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status ENUM('joined', 'left', 'cancelled') NOT NULL DEFAULT 'joined',
    UNIQUE KEY unique_event_user (event_id, user_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- User Posts
-- ---------------------------------------------------------------------------------
CREATE TABLE posts (
    post_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    post_content TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Post Images
-- ---------------------------------------------------------------------------------
CREATE TABLE post_images (
    image_id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    order_index INT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    visibility VARCHAR(16) NOT NULL DEFAULT 'friends',
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE
);



-- ---------------------------------------------------------------------------------
-- Post Likes System
-- ---------------------------------------------------------------------------------
CREATE TABLE post_likes (
    like_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_post_like (user_id, post_id)
);

-- =================================================================================
-- MESSAGING SYSTEM TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Chat Rooms
-- ---------------------------------------------------------------------------------
CREATE TABLE chats (
    chat_id INT AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------------
-- User Chat Locks
-- ---------------------------------------------------------------------------------
CREATE TABLE user_chat_locks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    chat_id INT NOT NULL,
    is_locked BOOLEAN DEFAULT TRUE NOT NULL,
    pin_hash VARCHAR(255) NULL,
    lock_type VARCHAR(20) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY _user_chat_lock_uc (user_id, chat_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE
);


-- ---------------------------------------------------------------------------------
-- Chat Participation
-- ---------------------------------------------------------------------------------
CREATE TABLE chat_participants (
    chat_participant_id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    user_id INT NOT NULL,
    cleared_at DATETIME NULL,
    is_in_chat BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE KEY unique_chat_user (chat_id, user_id),
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Friend-Chat Mapping
-- ---------------------------------------------------------------------------------
CREATE TABLE friend_chat_map (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    friend_id INT NOT NULL,
    chat_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Messages
-- ---------------------------------------------------------------------------------
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    sender_id INT NOT NULL,
    message_text TEXT NOT NULL,
    sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted_by_sender BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted_by_receiver BOOLEAN NOT NULL DEFAULT FALSE,
    -- Encryption Fields ---
    iv VARCHAR(64) NULL, -- Initialization Vector for AES
    sender_enc_key TEXT NULL, -- The AES key encrypted with Sender's Public Key
    receiver_enc_key TEXT NULL, -- The AES key encrypted with Receiver's Public Key
    -- End Encryption Fields ---
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- User Blocking System
-- ---------------------------------------------------------------------------------
CREATE TABLE blocked_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    blocker_id INT NOT NULL,
    blocked_id INT NOT NULL,
    chat_id INT NULL,
    reason VARCHAR(255) NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at DATETIME NULL,
    UNIQUE KEY unique_blocker_blocked (blocker_id, blocked_id),
    FOREIGN KEY (blocker_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------------
-- Encryption & Security Tables
-- ---------------------------------------------------------------------------------

-- =================================================================================
-- SOCIAL FEATURES TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Friend System
-- ---------------------------------------------------------------------------------
CREATE TABLE friendships (
    friendship_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id1 INT NOT NULL,
    user_id2 INT NOT NULL,
    status ENUM('pending', 'accepted', 'blocked') NOT NULL DEFAULT 'pending',
    action_user_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user1_user2 (user_id1, user_id2),
    FOREIGN KEY (user_id1) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id2) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (action_user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Notifications System
-- ---------------------------------------------------------------------------------
CREATE TABLE notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type VARCHAR(50) NOT NULL,
    source_id INT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- =================================================================================
-- ADMINISTRATION TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- User Reports & Moderation
-- ---------------------------------------------------------------------------------
CREATE TABLE reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    reporter_id INT NOT NULL,
    reported_user_id INT NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    admin_notes TEXT NULL,
    FOREIGN KEY (reporter_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (reported_user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------
-- Admin Activity Tracking
-- ---------------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------------
-- User Activity Logs
-- ---------------------------------------------------------------------------------
CREATE TABLE user_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    log_type VARCHAR(100) NOT NULL,
    log_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- =================================================================================
-- SECURITY & MONITORING TABLES
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- ModSecurity Logs
-- ---------------------------------------------------------------------------------
CREATE TABLE ModSecLog (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date VARCHAR(20) NOT NULL,
    time VARCHAR(20) NOT NULL,
    source VARCHAR(50) NOT NULL,
    request TEXT NOT NULL,
    response TEXT NOT NULL,
    attack_detected TEXT NOT NULL
);

-- ---------------------------------------------------------------------------------
-- Error Logs
-- ---------------------------------------------------------------------------------
CREATE TABLE ErrorLog (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date VARCHAR(20) NOT NULL,
    time VARCHAR(20) NOT NULL,
    level ENUM('notice', 'error', 'warning', 'critical') NOT NULL,
    message TEXT NOT NULL,
    client_ip VARCHAR(50) NOT NULL
);

-- =================================================================================
-- DATABASE INDEXES FOR PERFORMANCE
-- =================================================================================

-- Ticketing System Indexes
CREATE INDEX idx_tickets_user_id ON tickets(user_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_priority ON tickets(priority);
CREATE INDEX idx_tickets_classification ON tickets(classification);
CREATE INDEX idx_tickets_created_at ON tickets(created_at);
CREATE INDEX idx_tickets_archived_at ON tickets(archived_at);
CREATE INDEX idx_ticket_assignments_ticket_id ON ticket_assignments(ticket_id);
CREATE INDEX idx_ticket_assignments_agent_id ON ticket_assignments(agent_id);
CREATE INDEX idx_ticket_messages_ticket_id ON ticket_messages(ticket_id);
CREATE INDEX idx_support_agents_user_id ON support_agents(user_id);
CREATE INDEX idx_support_agents_clearance_level ON support_agents(clearance_level);

-- Archived Tickets Indexes
CREATE INDEX idx_archived_tickets_user_id ON archived_tickets(user_id);
CREATE INDEX idx_archived_tickets_classification ON archived_tickets(classification);
CREATE INDEX idx_archived_tickets_archived_at ON archived_tickets(archived_at);
CREATE INDEX idx_archived_tickets_original_id ON archived_tickets(original_ticket_id);

-- Social Media Indexes
CREATE INDEX idx_post_likes_user_id ON post_likes(user_id);
CREATE INDEX idx_post_likes_post_id ON post_likes(post_id);
CREATE INDEX idx_post_likes_created_at ON post_likes(created_at);

-- Re-enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- =================================================================================
-- INITIAL DATA POPULATION
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- Clearance Levels Configuration
-- ---------------------------------------------------------------------------------

INSERT INTO clearance_levels (level_id, level_name, level_description, can_view_public, can_view_internal, can_view_confidential, can_view_secret, can_view_top_secret) VALUES
(1, 'PUBLIC', 'Public clearance - can view public tickets only', TRUE, FALSE, FALSE, FALSE, FALSE),
(2, 'INTERNAL', 'Internal clearance - can view public and internal tickets', TRUE, TRUE, FALSE, FALSE, FALSE),
(3, 'CONFIDENTIAL', 'Confidential clearance - can view public, internal, and confidential tickets', TRUE, TRUE, TRUE, FALSE, FALSE),
(4, 'SECRET', 'Secret clearance - can view public, internal, confidential, and secret tickets', TRUE, TRUE, TRUE, TRUE, FALSE),
(5, 'TOP_SECRET', 'Top Secret clearance - can view all ticket classifications', TRUE, TRUE, TRUE, TRUE, TRUE);

-- ---------------------------------------------------------------------------------
-- System Roles
-- ---------------------------------------------------------------------------------
INSERT INTO roles (role_name, description) VALUES
('admin', 'Full administrative privileges over the system'),
('user', 'Standard user with basic functionality'),
('support_agent', 'Support agent with ticketing system access'),
('guest', 'Limited access for viewing public content only');

-- ---------------------------------------------------------------------------------
-- System Permissions
-- ---------------------------------------------------------------------------------
INSERT INTO permissions (permission_name, description) VALUES
('manage_users', 'Create, update, and delete user accounts'),
('delete_any_post', 'Delete any post in the system'),
('edit_any_post', 'Edit any post in the system'),
('create_post', 'Create new posts'),
('create_event', 'Create new events/reminders'),
('send_message', 'Send private messages'),
('view_admin_panel', 'Access administrative dashboard'),
('resolve_reports', 'Change status of user-submitted reports'),
('access_ticketing_dashboard', 'Access support ticketing dashboard'),
('manage_tickets', 'Assign, escalate, and close tickets'),
('view_all_tickets', 'View tickets based on clearance level'),
('escalate_tickets', 'Escalate ticket priority levels'),
('assign_tickets', 'Assign tickets to other agents'),
('view_internal_notes', 'View internal agent notes on tickets'),
('view_open_tickets', 'View open tickets based on clearance level'),
('view_my_tickets', 'View assigned tickets'),
('archive_tickets', 'Archive tickets with read-only access'),
('view_archived_tickets', 'View archived tickets based on clearance level'),
('terminate_tickets', 'Permanently delete tickets (audit trail maintained)');

-- ---------------------------------------------------------------------------------
-- Role-Permission Assignments
-- ---------------------------------------------------------------------------------
-- Admin Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'admin' AND p.permission_name IN (
    'manage_users', 'delete_any_post', 'edit_any_post', 'create_post',
    'create_event', 'send_message', 'view_admin_panel', 'resolve_reports',
    'access_ticketing_dashboard', 'manage_tickets', 'view_all_tickets',
    'escalate_tickets', 'assign_tickets', 'view_internal_notes',
    'view_open_tickets', 'view_my_tickets', 'archive_tickets',
    'view_archived_tickets', 'terminate_tickets'
);

-- Support Agent Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'support_agent' AND p.permission_name IN (
    'access_ticketing_dashboard', 'manage_tickets', 'view_all_tickets',
    'escalate_tickets', 'assign_tickets', 'view_internal_notes',
    'view_open_tickets', 'view_my_tickets', 'archive_tickets',
    'view_archived_tickets'
);

-- User Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'user' AND p.permission_name IN (
    'create_post', 'create_event', 'send_message'
);

-- ---------------------------------------------------------------------------------
-- Sample User Accounts
-- ---------------------------------------------------------------------------------
INSERT INTO users (username, phone_number, password_hash) VALUES
('admin', '12345679', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('user', '12345678', 'scrypt:32768:8:1$V460O7kVZYEBrWGC$d7a6bd9c8feced05b6d118ec8ef7d2c65c66d41171eb05c9589a49e60a95fda7d830ed98d7eb2e50830034bea978f6db05be620883bacb0bf4c5fc3a0e1d7b38'),
('user2', '11145671', 'scrypt:32768:8:1$xdPsxX7EC8sCphaO$f1b46069ede337b2b1f594c10680a3f85ab5906faa04af144994218cfa039e75a9aacf64e19b928be1661a5a1e53c5987f935131c1b8bbaece6b266c1a553160'),
('user3', '12345656', 'scrypt:32768:8:1$xdPsxX7EC8sCphaO$f1b46069ede337b2b1f594c10680a3f85ab5906faa04af144994218cfa039e75a9aacf64e19b928be1661a5a1e53c5987f935131c1b8bbaece6b266c1a553160'),
('user4', '11141671', 'scrypt:32768:8:1$xdPsxX7EC8sCphaO$f1b46069ede337b2b1f594c10680a3f85ab5906faa04af144994218cfa039e75a9aacf64e19b928be1661a5a1e53c5987f935131c1b8bbaece6b266c1a553160');

-- Support Agent Accounts
INSERT INTO users (username, phone_number, password_hash) VALUES
('support_public_agent', '98765421', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_internal_agent', '98765422', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_confidential_agent', '98765423', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_secret_agent', '98765424', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('support_topsecret_agent', '98765425', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b');

-- ---------------------------------------------------------------------------------
-- Database Management User
-- ---------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'orchestrator'@'%' IDENTIFIED BY 'orchestrator_password';
GRANT SUPER, PROCESS, REPLICATION SLAVE, REPLICATION CLIENT, RELOAD ON *.* TO 'orchestrator'@'%';
GRANT SELECT ON mysql.slave_master_info TO 'orchestrator'@'%';
GRANT SELECT ON performance_schema.replication_group_members TO 'orchestrator'@'%';
GRANT SELECT ON performance_schema.replication_group_member_stats TO 'orchestrator'@'%';
GRANT SELECT ON performance_schema.global_variables TO 'orchestrator'@'%';
FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------------------
-- User-Role Assignments
-- ---------------------------------------------------------------------------------
-- Admin and regular users
INSERT INTO user_role_assignments (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE (u.username = 'admin' AND r.role_name IN ('admin', 'user'))
   OR (u.username IN ('user', 'user2', 'user3', 'user4') AND r.role_name = 'user');

-- Support agents get both user and support_agent roles
INSERT INTO user_role_assignments (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE u.username IN ('support_public_agent', 'support_internal_agent', 'support_confidential_agent', 'support_secret_agent', 'support_topsecret_agent') 
AND r.role_name IN ('user', 'support_agent');

-- ---------------------------------------------------------------------------------
-- Ticket Categories
-- ---------------------------------------------------------------------------------
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
('Emergency Support', 'Urgent emergency situations', 'critical', 4),
('Security Breach Investigation', 'Active security breaches and forensic investigations', 'security', 5),
('Classified Data Incidents', 'Incidents involving classified or top secret information', 'security', 5),
('Intelligence Operations Support', 'Support for intelligence and surveillance operations', 'security', 5);

-- ---------------------------------------------------------------------------------
-- Support Agents with Clearance Levels
-- ---------------------------------------------------------------------------------
INSERT INTO support_agents (user_id, clearance_level, department, specialization, created_by) VALUES
((SELECT user_id FROM users WHERE username = 'support_public_agent'), 1, 'Customer Service', 'General Inquiries, Account Issues, Basic Troubleshooting', 1),
((SELECT user_id FROM users WHERE username = 'support_internal_agent'), 2, 'Technical Support', 'Software Issues, API Support, Integration Problems', 1),
((SELECT user_id FROM users WHERE username = 'support_confidential_agent'), 3, 'Senior Technical Support', 'Complex Technical Issues, System Administration, Advanced Troubleshooting', 1),
((SELECT user_id FROM users WHERE username = 'support_secret_agent'), 4, 'Critical Response Team', 'System Outages, Critical Bugs, Emergency Response, Infrastructure Issues', 1),
((SELECT user_id FROM users WHERE username = 'support_topsecret_agent'), 5, 'Security Team', 'Security Incidents, Breach Response, Vulnerability Management, Compliance', 1);

-- ---------------------------------------------------------------------------------
-- Sample Tickets with Classifications
-- ---------------------------------------------------------------------------------
INSERT INTO tickets (user_id, title, description, category_id, priority, classification, status) VALUES
((SELECT user_id FROM users WHERE username = 'user'), 'Password Reset Request', 'I forgot my password and cannot login to my account', 3, 'low', 'public', 'open'),
((SELECT user_id FROM users WHERE username = 'user2'), 'API Integration Issue', 'Having trouble with the REST API authentication', 9, 'medium', 'internal', 'open'),
((SELECT user_id FROM users WHERE username = 'user3'), 'System Performance Problem', 'The application is running very slowly', 2, 'high', 'confidential', 'open'),
((SELECT user_id FROM users WHERE username = 'user4'), 'Database Connection Failure', 'Cannot connect to database - system down', 7, 'critical', 'secret', 'open'),
((SELECT user_id FROM users WHERE username = 'user'), 'Suspicious Login Activity', 'Noticed unauthorized login attempts from unknown IP addresses', 6, 'security', 'top_secret', 'open'),
((SELECT user_id FROM users WHERE username = 'user2'), 'Feature Request', 'Would like to see dark mode option', 5, 'low', 'public', 'open'),
((SELECT user_id FROM users WHERE username = 'user3'), 'Billing Question', 'Question about my monthly subscription charge', 4, 'medium', 'internal', 'open'),
((SELECT user_id FROM users WHERE username = 'user4'), 'Data Export Request', 'Need to export my personal data', 8, 'high', 'confidential', 'open');

-- ---------------------------------------------------------------------------------
-- Sample Ticket Assignments
-- ---------------------------------------------------------------------------------
INSERT INTO ticket_assignments (ticket_id, agent_id, assigned_by, assigned_at, is_active) VALUES
(1, 1, 1, NOW(), TRUE),  -- Public ticket to PUBLIC agent
(2, 2, 1, NOW(), TRUE),  -- Internal ticket to INTERNAL agent  
(3, 3, 1, NOW(), TRUE),  -- Confidential ticket to CONFIDENTIAL agent
(4, 4, 1, NOW(), TRUE),  -- Secret ticket to SECRET agent
(5, 5, 1, NOW(), TRUE);  -- Top secret ticket to TOP_SECRET agent

-- ---------------------------------------------------------------------------------
-- Sample Archived Tickets (Closed tickets moved to archive)
-- ---------------------------------------------------------------------------------
INSERT INTO archived_tickets (original_ticket_id, user_id, title, description, category_id, priority, status, classification, resolution, created_at, updated_at, resolved_at, archived_by) VALUES
(101, (SELECT user_id FROM users WHERE username = 'user'), 'Resolved Password Issue', 'Password reset was successfully completed', 3, 'low', 'closed', 'public', 'Password reset link sent and user successfully logged in', '2024-11-01 10:00:00', '2024-11-01 11:30:00', '2024-11-01 11:30:00', 1),
(102, (SELECT user_id FROM users WHERE username = 'user2'), 'Fixed API Authentication', 'API authentication issue resolved', 9, 'medium', 'closed', 'internal', 'Updated API documentation and provided new authentication tokens', '2024-11-02 14:00:00', '2024-11-02 16:45:00', '2024-11-02 16:45:00', 2),
(103, (SELECT user_id FROM users WHERE username = 'user3'), 'Performance Optimization Complete', 'System performance issues have been resolved', 2, 'high', 'closed', 'confidential', 'Optimized database queries and increased server capacity', '2024-11-03 09:00:00', '2024-11-03 18:30:00', '2024-11-03 18:30:00', 3);

-- =================================================================================
-- END OF DATABASE SCHEMA
-- =================================================================================