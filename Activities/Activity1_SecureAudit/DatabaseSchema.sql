-- SafeVault Activity 1: Secure Database Schema
-- This schema demonstrates secure database design patterns

-- Create users table with proper constraints
CREATE TABLE users (
    user_id INT PRIMARY KEY IDENTITY(1,1),
    username NVARCHAR(50) NOT NULL UNIQUE,
    email NVARCHAR(255) NOT NULL UNIQUE,
    password_hash NVARCHAR(255) NOT NULL, -- Store hashed passwords only
    salt NVARCHAR(255) NOT NULL,         -- Individual salt per user
    created_at DATETIME2 DEFAULT GETDATE(),
    last_login DATETIME2,
    is_active BIT DEFAULT 1,
    failed_login_attempts INT DEFAULT 0,
    lockout_until DATETIME2 NULL,
    
    -- Security constraints
    CONSTRAINT CHK_username_length CHECK (LEN(username) >= 3),
    CONSTRAINT CHK_email_format CHECK (email LIKE '%_@_%.__%')
);

-- Create audit log table for security monitoring
CREATE TABLE security_audit (
    audit_id BIGINT PRIMARY KEY IDENTITY(1,1),
    user_id INT NULL,
    event_type NVARCHAR(50) NOT NULL,
    event_description NVARCHAR(500),
    ip_address NVARCHAR(45),
    user_agent NVARCHAR(500),
    timestamp DATETIME2 DEFAULT GETDATE(),
    severity_level NVARCHAR(20) DEFAULT 'INFO',
    
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Example of parameterized query procedure (prevents SQL injection)
CREATE PROCEDURE GetUserByCredentials
    @Username NVARCHAR(50),
    @PasswordHash NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Secure query using parameters
    SELECT 
        user_id,
        username,
        email,
        is_active,
        failed_login_attempts,
        lockout_until
    FROM users 
    WHERE username = @Username 
      AND password_hash = @PasswordHash
      AND is_active = 1
      AND (lockout_until IS NULL OR lockout_until < GETDATE());
END;

-- Example of secure audit logging
CREATE PROCEDURE LogSecurityEvent
    @UserId INT = NULL,
    @EventType NVARCHAR(50),
    @Description NVARCHAR(500),
    @IPAddress NVARCHAR(45),
    @UserAgent NVARCHAR(500),
    @SeverityLevel NVARCHAR(20) = 'INFO'
AS
BEGIN
    SET NOCOUNT ON;
    
    INSERT INTO security_audit 
    (user_id, event_type, event_description, ip_address, user_agent, severity_level)
    VALUES 
    (@UserId, @EventType, @Description, @IPAddress, @UserAgent, @SeverityLevel);
END;

-- Index for performance and security
CREATE INDEX IX_users_email ON users(email);
CREATE INDEX IX_audit_timestamp ON security_audit(timestamp);
CREATE INDEX IX_audit_event_type ON security_audit(event_type);

-- Sample secure data (passwords are pre-hashed)
INSERT INTO users (username, email, password_hash, salt) VALUES 
('admin', 'admin@safevault.com', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'randomsalt123'),
('testuser', 'test@safevault.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'randomsalt456');

-- Security best practices demonstrated:
-- 1. Input validation via constraints
-- 2. Parameterized queries in stored procedures
-- 3. Password hashing with salts
-- 4. Audit logging for security events
-- 5. Account lockout mechanism
-- 6. Proper indexing for security queries
