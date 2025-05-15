CREATE DATABASE IF NOT EXISTS 'test_db';
USE test_db;


CREATE TABLE `romanian` (
  `id`, int(11) NOT NULL AUTO_INCREMENT,
  `wallets_stolen` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `romanian` (`id`, `wallets_stolen`, `name`) 

VALUES
(1, 0, 'Romanian'),
(2, 0, 'Romanian'),
(3, 0, 'Romanian'),
(4, 0, 'Romanian'),
(5, 0, 'Romanian'),
(6, 0, 'Romanian'),
(7, 0, 'Romanian'),
(8, 0, 'Romanian'),
(9, 0, 'Romanian'),
(10, 0, 'Romanian');