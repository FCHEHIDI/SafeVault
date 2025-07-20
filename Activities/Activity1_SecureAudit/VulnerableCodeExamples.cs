using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace SafeVault.Activity1.Vulnerable
{
    /// <summary>
    /// ❌ VULNERABLE DATABASE EXAMPLES - DO NOT USE IN PRODUCTION
    /// This class demonstrates common database security vulnerabilities for educational purposes
    /// </summary>
    public class VulnerableDatabaseExamples
    {
        private string connectionString = "Server=localhost;Database=SafeVault;Trusted_Connection=true;";

        #region SQL Injection Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Direct string concatenation allows SQL injection
        /// Attack vector: userInput = "'; DROP TABLE Users; --"
        /// </summary>
        public DataTable GetUserByUsername_Vulnerable(string username)
        {
            string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
            
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                SqlDataAdapter adapter = new SqlDataAdapter(command);
                DataTable result = new DataTable();
                
                connection.Open();
                adapter.Fill(result);
                return result;
            }
        }

        /// <summary>
        /// ❌ VULNERABLE: String formatting is still vulnerable to injection
        /// Attack vector: userId = "1 OR 1=1"
        /// </summary>
        public bool AuthenticateUser_Vulnerable(string username, string password)
        {
            string query = string.Format("SELECT COUNT(*) FROM Users WHERE Username = '{0}' AND Password = '{1}'", 
                username, password);
            
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                connection.Open();
                
                int count = (int)command.ExecuteScalar();
                return count > 0;
            }
        }

        /// <summary>
        /// ❌ VULNERABLE: Dynamic ORDER BY clause injection
        /// Attack vector: sortColumn = "Username; DROP TABLE Users; --"
        /// </summary>
        public DataTable GetUsersSorted_Vulnerable(string sortColumn)
        {
            string query = "SELECT * FROM Users ORDER BY " + sortColumn;
            
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                SqlDataAdapter adapter = new SqlDataAdapter(command);
                DataTable result = new DataTable();
                
                connection.Open();
                adapter.Fill(result);
                return result;
            }
        }

        #endregion

        #region Poor Error Handling

        /// <summary>
        /// ❌ VULNERABLE: Exposes sensitive database information in error messages
        /// </summary>
        public string GetDatabaseInfo_Vulnerable()
        {
            try
            {
                string query = "SELECT @@VERSION, USER_NAME(), DB_NAME()";
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    SqlCommand command = new SqlCommand(query, connection);
                    connection.Open();
                    
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return $"Database: {reader[2]}, User: {reader[1]}, Version: {reader[0]}";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // ❌ VULNERABLE: Exposes full exception details to user
                throw new Exception($"Database error: {ex.Message}\nConnection: {connectionString}\nStack: {ex.StackTrace}");
            }
            
            return string.Empty;
        }

        #endregion

        #region Insecure Connection Management

        /// <summary>
        /// ❌ VULNERABLE: Connection string with embedded credentials
        /// </summary>
        public class InsecureConnectionManager
        {
            // ❌ VULNERABLE: Hardcoded credentials, no encryption
            private const string INSECURE_CONNECTION = 
                "Server=production-server;Database=SafeVault;User Id=sa;Password=admin123;";
            
            /// <summary>
            /// ❌ VULNERABLE: Shares connection across requests without proper isolation
            /// </summary>
            private static SqlConnection sharedConnection;
            
            public static SqlConnection GetConnection_Vulnerable()
            {
                if (sharedConnection == null || sharedConnection.State != ConnectionState.Open)
                {
                    sharedConnection = new SqlConnection(INSECURE_CONNECTION);
                    sharedConnection.Open();
                }
                return sharedConnection;
            }
        }

        #endregion

        #region Insecure Data Access Patterns

        /// <summary>
        /// ❌ VULNERABLE: No input validation or sanitization
        /// </summary>
        public void UpdateUserProfile_Vulnerable(int userId, string firstName, string lastName, string email)
        {
            // ❌ No validation on input parameters
            string query = $@"
                UPDATE Users 
                SET FirstName = '{firstName}', 
                    LastName = '{lastName}', 
                    Email = '{email}'
                WHERE UserId = {userId}";
            
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                connection.Open();
                command.ExecuteNonQuery();
                // ❌ No verification that update affected correct number of rows
            }
        }

        /// <summary>
        /// ❌ VULNERABLE: Retrieves sensitive data without access control
        /// </summary>
        public DataTable GetAllUserData_Vulnerable()
        {
            // ❌ Returns all user data including passwords, no filtering
            string query = "SELECT * FROM Users"; // Includes password hashes!
            
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                SqlDataAdapter adapter = new SqlDataAdapter(command);
                DataTable result = new DataTable();
                
                connection.Open();
                adapter.Fill(result);
                return result; // ❌ Returns sensitive data to caller
            }
        }

        #endregion

        #region Logging Security Issues

        /// <summary>
        /// ❌ VULNERABLE: Logs sensitive information
        /// </summary>
        public void LogUserActivity_Vulnerable(string username, string action, string sensitiveData)
        {
            string logEntry = $"[{DateTime.Now}] User: {username}, Action: {action}, Data: {sensitiveData}";
            
            // ❌ VULNERABLE: Logs sensitive data to plain text file
            System.IO.File.AppendAllText("C:\\Logs\\activity.log", logEntry + Environment.NewLine);
            
            // ❌ VULNERABLE: Also logs to console (visible in production)
            Console.WriteLine($"SECURITY LOG: {logEntry}");
        }

        #endregion
    }

    #region Vulnerable Database Schema Examples

    /// <summary>
    /// ❌ POOR DATABASE DESIGN EXAMPLES
    /// These demonstrate common database security and design flaws
    /// </summary>
    public static class PoorDatabaseSchema
    {
        /// <summary>
        /// ❌ VULNERABLE TABLE STRUCTURE
        /// Multiple security and design issues in this schema
        /// </summary>
        public const string POOR_USERS_TABLE_DDL = @"
-- ❌ POOR EXAMPLE - Multiple Security Issues
CREATE TABLE Users (
    UserId int IDENTITY(1,1) PRIMARY KEY,
    Username varchar(50),                    -- ❌ No uniqueness constraint
    Password varchar(255),                   -- ❌ Storing plain text passwords
    Email varchar(100),                      -- ❌ No email validation
    FirstName varchar(50),                   -- ❌ No length limits
    LastName varchar(50),                    -- ❌ Allows NULL critical fields
    PhoneNumber varchar(20),                 -- ❌ No format validation
    SocialSecurityNumber varchar(11),        -- ❌ Storing SSN without encryption
    CreditCardNumber varchar(20),            -- ❌ Storing CC numbers (PCI violation)
    Salary decimal(10,2),                    -- ❌ Sensitive salary data unprotected
    Role varchar(20) DEFAULT 'User',         -- ❌ Basic role system, no granular permissions
    IsActive bit DEFAULT 1,                  -- ❌ Soft delete without audit trail
    CreatedDate datetime DEFAULT GETDATE(),  -- ❌ No timezone handling
    LastLogin datetime,                      -- ❌ No failed login tracking
    Comments text                            -- ❌ Unlimited text field, XSS risk
);

-- ❌ POOR PERMISSIONS
GRANT ALL ON Users TO PUBLIC;  -- ❌ Everyone has full access!

-- ❌ NO INDEXES on frequently queried columns
-- ❌ NO CHECK CONSTRAINTS for data validation
-- ❌ NO FOREIGN KEY relationships defined
-- ❌ NO AUDIT TRIGGERS for tracking changes
";

        /// <summary>
        /// ❌ VULNERABLE STORED PROCEDURES
        /// </summary>
        public const string POOR_STORED_PROCEDURES = @"
-- ❌ VULNERABLE STORED PROCEDURE - SQL Injection Risk
CREATE PROCEDURE GetUserByName_Vulnerable
    @Username VARCHAR(50)
AS
BEGIN
    -- ❌ Dynamic SQL construction = SQL injection risk
    DECLARE @SQL NVARCHAR(MAX)
    SET @SQL = 'SELECT * FROM Users WHERE Username = ''' + @Username + ''''
    EXEC sp_executesql @SQL
END;

-- ❌ POOR ACCESS CONTROL PROCEDURE
CREATE PROCEDURE AuthenticateUser_Poor
    @Username VARCHAR(50),
    @Password VARCHAR(255)
AS
BEGIN
    -- ❌ No rate limiting, no account lockout
    -- ❌ Returns full user record including sensitive data
    SELECT * FROM Users 
    WHERE Username = @Username AND Password = @Password
    
    -- ❌ No logging of authentication attempts
    -- ❌ Vulnerable to timing attacks
END;

-- ❌ DANGEROUS ADMIN PROCEDURE
CREATE PROCEDURE ExecuteArbitrarySQL_Dangerous
    @SQL NVARCHAR(MAX)
AS
BEGIN
    -- ❌ NEVER DO THIS - Allows execution of any SQL!
    EXEC sp_executesql @SQL
END;
";

        /// <summary>
        /// ❌ POOR DATABASE CONFIGURATION
        /// </summary>
        public const string POOR_DATABASE_CONFIG = @"
-- ❌ POOR DATABASE CONFIGURATION EXAMPLES

-- ❌ Weak authentication modes
sp_configure 'mixed_mode_authentication', 1;

-- ❌ Enabling dangerous features
sp_configure 'xp_cmdshell', 1;
sp_configure 'Ole Automation Procedures', 1;
sp_configure 'Ad Hoc Distributed Queries', 1;

-- ❌ No connection encryption required
sp_configure 'force_encryption', 0;

-- ❌ Weak password policies
sp_configure 'password_policy', 0;
sp_configure 'password_expiration', 0;

-- ❌ Excessive permissions
CREATE LOGIN [Everyone] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [Everyone];

-- ❌ No backup encryption
BACKUP DATABASE SafeVault TO DISK = 'C:\Backup\SafeVault.bak'
WITH INIT; -- ❌ Unencrypted backup

-- ❌ Audit disabled
ALTER DATABASE SafeVault SET AUDIT OFF;
";
    }

    #endregion
}
