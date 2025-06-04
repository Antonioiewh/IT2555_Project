-- Disable foreign key checks for a clean start (highly recommended when dropping and recreating related tables)
SET FOREIGN_KEY_CHECKS = 0;

-- Drop tables in reverse dependency order to avoid foreign key constraint issues
DROP TABLE IF EXISTS user_role_assignments;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS posts;         -- Assuming posts table exists and links to users
DROP TABLE IF EXISTS post_images;   -- Assuming post_images exists
DROP TABLE IF EXISTS post_likes;    -- Assuming post_likes exists
DROP TABLE IF EXISTS comments;      -- Assuming comments exists
DROP TABLE IF EXISTS events;        -- Assuming events exists
DROP TABLE IF EXISTS notifications; -- Assuming notifications exists
DROP TABLE IF EXISTS faq_categories;-- Assuming faq_categories exists
DROP TABLE IF EXISTS faqs;          -- Assuming faqs exists
DROP TABLE IF EXISTS reports;       -- Assuming reports exists
DROP TABLE IF EXISTS messages;      -- Assuming messages exists
DROP TABLE IF EXISTS chat_participants; -- Assuming chat_participants exists
DROP TABLE IF EXISTS chats;         -- Assuming chats exists
DROP TABLE IF EXISTS friendships;   -- Assuming friendships exists
DROP TABLE IF EXISTS admin_actions; -- Assuming admin_actions exists
DROP TABLE IF EXISTS user_logs;     -- Assuming user_logs exists

DROP TABLE IF EXISTS users; -- Drop users table last

-- **************************************
-- 1. User Accounts
-- **************************************
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY, -- Renamed 'id' to 'user_id' for consistency with schema
    username VARCHAR(80) UNIQUE NOT NULL,
    phone_number VARCHAR(8) UNIQUE NULL, -- Added phone number as per the full schema
    password_hash VARCHAR(255) NOT NULL,        -- Added as per the full schema
    profile_pic_url VARCHAR(255) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_active_at DATETIME DEFAULT NULL
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
    is_reminder BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (post_id, user_id), -- A user can like a post only once
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE comments (
    comment_id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    comment_text TEXT NOT NULL,
    parent_comment_id INT NULL, -- For nested comments
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (parent_comment_id) REFERENCES comments(comment_id) ON DELETE CASCADE
);

-- **************************************
-- 5. Notifications
-- **************************************
CREATE TABLE notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('like', 'comment', 'friend_request', 'event_reminder', 'message', 'report_status', 'admin_override') NOT NULL,
    source_id INT NULL, -- ID of the related item (e.g., post_id, friendship_id)
    message VARCHAR(255) NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- **************************************
-- 6. Customer Service
-- **************************************
CREATE TABLE faq_categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE faqs (
    faq_id INT AUTO_INCREMENT PRIMARY KEY,
    category_id INT NULL,
    question VARCHAR(500) NOT NULL,
    answer TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES faq_categories(category_id) ON DELETE SET NULL
);

CREATE TABLE reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL, -- NULL if anonymous
    report_type ENUM('bug', 'feature_request', 'abuse', 'other') NOT NULL,
    description TEXT NOT NULL,
    status ENUM('open', 'in_progress', 'closed', 'rejected') NOT NULL DEFAULT 'open',
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    admin_notes TEXT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- **************************************
-- 7. Messaging
-- **************************************
CREATE TABLE chats (
    chat_id INT AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE chat_participants (
    chat_participant_id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    user_id INT NOT NULL,
    UNIQUE (chat_id, user_id),
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
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

-- **************************************
-- 8. Friend System
-- **************************************
CREATE TABLE friendships (
    friendship_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id1 INT NOT NULL,
    user_id2 INT NOT NULL,
    status ENUM('pending', 'accepted', 'blocked') NOT NULL DEFAULT 'pending',
    action_user_id INT NOT NULL, -- User who initiated the last status change
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE (user_id1, user_id2), -- Ensures no duplicate friendship entries (enforce user_id1 < user_id2 in application logic)
    FOREIGN KEY (user_id1) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id2) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (action_user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- **************************************
-- 9. Admin Panel
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
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    log_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);


-- Enable foreign key checks again
SET FOREIGN_KEY_CHECKS = 1;

-- Commit changes (optional, usually auto-committed in MySQL)
-- COMMIT;

-- **************************************
-- Sample Data Insertion for Roles and Permissions
-- **************************************

-- Insert sample roles
INSERT INTO roles (role_name, description) VALUES
('admin', 'Has full administrative privileges over the system.'),
('editor', 'Can create, edit, and delete posts and comments, potentially moderate content.'),
('user', 'Standard user with basic functionality like creating posts, events, sending messages.'),
('guest', 'Can view public content but cannot interact or create.');

-- Insert sample permissions (just a few examples)
INSERT INTO permissions (permission_name, description) VALUES
('manage_users', 'Ability to create, update, and delete user accounts.'),
('delete_any_post', 'Ability to delete any post in the system.'),
('edit_any_post', 'Ability to edit any post in the system.'),
('create_post', 'Ability to create new posts.'),
('create_event', 'Ability to create new events/reminders.'),
('send_message', 'Ability to send private messages.'),
('view_admin_panel', 'Ability to access the administrative dashboard.'),
('resolve_reports', 'Ability to change the status of user-submitted reports.');

-- Assign permissions to roles
-- Admin Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'admin' AND p.permission_name IN (
    'manage_users', 'delete_any_post', 'edit_any_post', 'create_post',
    'create_event', 'send_message', 'view_admin_panel', 'resolve_reports'
);

-- Editor Role Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'editor' AND p.permission_name IN (
    'create_post', 'edit_any_post', 'delete_any_post', 'create_event', 'send_message'
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

INSERT INTO users (username, phone_number, password_hash) VALUES
('admin', '12345678', 'scrypt:32768:8:1$YdRtcucyAyW3tI1d$899340e99d8dbb95933503f9b6e8e89613bfb9c96d0069d1db13d1a4e32b231bb3b29a29db2b0e231b3a29599f9a2809c960c01edf2b916d075dc4343d69db1b'),
('editor', '12345678', 'scrypt:32768:8:1$MACB13gQmz07eh4r$70fe403cc30e93c0605e8c1b5ecf64c43698b421268327e7a18cba40a3e5c25093d399ddbf774653715e2decbf3605d917a749a450dc60790d4e12c3e42c588d'),
('user', '12345678', 'scrypt:32768:8:1$V460O7kVZYEBrWGC$d7a6bd9c8feced05b6d118ec8ef7d2c65c66d41171eb05c9589a49e60a95fda7d830ed98d7eb2e50830034bea978f6db05be620883bacb0bf4c5fc3a0e1d7b38');

-- Assign roles to the newly created users
INSERT INTO user_role_assignments (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE (u.username = 'admin' AND r.role_name IN ('user', 'editor', 'admin'))
   OR (u.username = 'editor' AND r.role_name IN ('user', 'editor'))
   OR (u.username = 'user' AND r.role_name = 'user');