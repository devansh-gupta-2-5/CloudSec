#!/bin/bash
echo "[*] Wiping all IP bans..."
redis-cli flushall

echo "[*] Wiping database and recreating schema..."
sudo mysql -e "
DROP DATABASE IF EXISTS cloudsec_db;
CREATE DATABASE cloudsec_db;
USE cloudsec_db;
CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, salt VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL);
CREATE TABLE files (id INT AUTO_INCREMENT PRIMARY KEY, filename VARCHAR(255) NOT NULL, owner_username VARCHAR(255) NOT NULL, stored_on_node VARCHAR(255) NOT NULL, encryption_iv VARCHAR(255) NOT NULL);
"
echo "[*] System reset complete! Ready for demo."