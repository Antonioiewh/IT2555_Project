-- =================================================================================
-- POST VISIBILITY MIGRATION SCRIPT
-- =================================================================================
-- This script adds the new post visibility system to an existing database
-- Run this script to migrate from the old system to the new post visibility system
-- =================================================================================

-- Add visibility column to posts table if it doesn't exist
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists 
FROM information_schema.columns 
WHERE table_schema = DATABASE() 
AND table_name = 'posts' 
AND column_name = 'visibility';

SET @sql = IF(@col_exists = 0, 
    'ALTER TABLE posts ADD COLUMN visibility ENUM(''public'', ''friends'', ''specific'') DEFAULT ''public''',
    'SELECT "Column visibility already exists" as message');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Create post_user_permissions table if it doesn't exist
CREATE TABLE IF NOT EXISTS post_user_permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by INT NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE KEY unique_post_user (post_id, user_id),
    INDEX idx_post_permissions_post_id (post_id),
    INDEX idx_post_permissions_user_id (user_id)
);

-- Update existing posts to have public visibility (if they don't have the column)
UPDATE posts SET visibility = 'public' WHERE visibility IS NULL;

-- Show migration status
SELECT 
    CASE 
        WHEN COUNT(*) > 0 THEN 'SUCCESS: Post visibility migration completed'
        ELSE 'ERROR: Migration may have failed'
    END as migration_status
FROM information_schema.columns 
WHERE table_schema = DATABASE() 
AND table_name = 'posts' 
AND column_name = 'visibility';

SELECT 
    CASE 
        WHEN COUNT(*) > 0 THEN 'SUCCESS: post_user_permissions table created'
        ELSE 'ERROR: post_user_permissions table creation failed'
    END as table_status
FROM information_schema.tables 
WHERE table_schema = DATABASE() 
AND table_name = 'post_user_permissions';