-- Create orchestrator user for topology monitoring in MAIN MySQL
CREATE USER IF NOT EXISTS 'orchestrator'@'%' IDENTIFIED BY 'orchestrator_password';

-- Grant necessary privileges for orchestrator to monitor MySQL topology
GRANT SELECT ON *.* TO 'orchestrator'@'%';
GRANT SUPER, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'orchestrator'@'%';
GRANT RELOAD ON *.* TO 'orchestrator'@'%';
GRANT PROCESS ON *.* TO 'orchestrator'@'%';

-- For MySQL 8.0+ compatibility
GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO 'orchestrator'@'%';

FLUSH PRIVILEGES;

-- Verify the user was created
SELECT user, host FROM mysql.user WHERE user='orchestrator';