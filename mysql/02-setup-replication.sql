-- Create replication user for slaves to connect to master
CREATE USER IF NOT EXISTS 'replication'@'%' IDENTIFIED BY 'replication_password';
GRANT REPLICATION SLAVE ON *.* TO 'replication'@'%';
FLUSH PRIVILEGES;

-- Create a table to track replication setup
CREATE TABLE IF NOT EXISTS flaskdb.replication_status (
    id INT PRIMARY KEY,
    setup_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    master_host VARCHAR(100)
);

INSERT INTO flaskdb.replication_status (id, master_host) VALUES (1, @@hostname) 
ON DUPLICATE KEY UPDATE setup_time = CURRENT_TIMESTAMP;