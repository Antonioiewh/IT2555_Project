-- Automatic slave setup with GTID
-- This script will attempt to setup replication, but will gracefully fail on master

-- Check if this is a slave (has read_only=1)
SET @is_slave = @@read_only;

-- Only proceed if this is a slave instance
SELECT IF(@is_slave = 1, 'Setting up slave replication...', 'Skipping - this is master') AS setup_status;

-- Wait for master to be ready (only on slaves)
SELECT IF(@is_slave = 1, SLEEP(15), 'Not waiting') AS wait_status;

-- Setup replication with GTID (only on slaves)
-- The master will skip this due to the conditional logic
SET @setup_replication = IF(@is_slave = 1, 
    'CHANGE MASTER TO MASTER_HOST=''mysql-master'', MASTER_USER=''replication'', MASTER_PASSWORD=''replication_password'', MASTER_AUTO_POSITION=1; START SLAVE;',
    'SELECT ''Master - no replication setup needed'' AS status;'
);

-- Execute the replication setup
PREPARE stmt FROM @setup_replication;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Show status (only meaningful on slaves)
SELECT IF(@is_slave = 1, 'Replication started', 'Master ready') AS final_status;