CREATE DATABASE IF NOT EXISTS user_management;
USE user_management;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
                                     id INT AUTO_INCREMENT PRIMARY KEY,
                                     name VARCHAR(100) NOT NULL,
                                     email VARCHAR(100) NOT NULL UNIQUE,
                                     password VARCHAR(255) NOT NULL,
                                     status ENUM('active', 'blocked') DEFAULT 'active',
                                     registrationTime DATETIME NOT NULL,
                                     lastLogin DATETIME NOT NULL,
                                     isAdmin BOOLEAN DEFAULT FALSE
);

-- Indexes for faster queries
CREATE INDEX idx_email ON users(email);
CREATE INDEX idx_status ON users(status);