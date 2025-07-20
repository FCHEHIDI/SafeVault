/* 
 * VulnerableCodeExamples.cs - Educational Security Testing
 * WARNING: This file contains INTENTIONALLY VULNERABLE code for educational purposes
 * 🚨 NEVER use these patterns in production applications! 🚨
 * 
 * Purpose: Demonstrate common security vulnerabilities that can be identified
 * and fixed using Microsoft Copilot assistance.
 */

using System.Data.SqlClient;
using System.Text;
using System.Web;

namespace SafeVault.VulnerableExamples
{
    /// <summary>
    /// ❌ VULNERABLE DATABASE CLASS - Educational Example Only
    /// Contains intentional SQL injection vulnerabilities for learning purposes
    /// Students should use Copilot to identify and fix these security issues
    /// </summary>
    public class VulnerableUserDatabase
    {
        private readonly string _connectionString;

        public VulnerableUserDatabase(string connectionString)
        {
            _connectionString = connectionString;
        }

        /// <summary>
        /// ❌ VULNERABLE: SQL Injection via string concatenation
        /// Copilot Exercise: Identify the security issue and suggest a parameterized query fix
        /// Attack Vector: username = "'; DROP TABLE Users; --"
        /// </summary>
        public User? GetUserByUsername(string username)
        {
            // 🚨 SECURITY VULNERABILITY: Direct string concatenation
            string query = "SELECT Id, Username, Email FROM Users WHERE Username = '" + username + "'";
            
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(query, connection);
            
            connection.Open();
            using var reader = command.ExecuteReader();
            
            if (reader.Read())
            {
                return new User
                {
                    Id = reader.GetInt32("Id"),
                    Username = reader.GetString("Username"),
                    Email = reader.GetString("Email")
                };
            }
            
            return null;
        }

        /// <summary>
        /// ❌ VULNERABLE: SQL Injection in login function
        /// Copilot Exercise: Fix this authentication bypass vulnerability
        /// Attack Vector: password = "' OR '1'='1"
        /// </summary>
        public bool AuthenticateUser(string username, string password)
        {
            // 🚨 SECURITY VULNERABILITY: Boolean-based SQL injection
            string query = $"SELECT COUNT(*) FROM Users WHERE Username = '{username}' AND Password = '{password}'";
            
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(query, connection);
            
            connection.Open();
            int count = (int)command.ExecuteScalar();
            
            return count > 0; // This can be bypassed with malicious input!
        }

        /// <summary>
        /// ❌ VULNERABLE: Dynamic SQL with user input
        /// Copilot Exercise: Convert to parameterized query or stored procedure
        /// Attack Vector: Multiple injection points in ORDER BY and WHERE clauses
        /// </summary>
        public List<User> SearchUsers(string searchTerm, string sortColumn = "Username")
        {
            // 🚨 SECURITY VULNERABILITY: Multiple injection points
            string query = $@"
                SELECT Id, Username, Email 
                FROM Users 
                WHERE Username LIKE '%{searchTerm}%' 
                OR Email LIKE '%{searchTerm}%'
                ORDER BY {sortColumn}";
            
            var users = new List<User>();
            
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(query, connection);
            
            connection.Open();
            using var reader = command.ExecuteReader();
            
            while (reader.Read())
            {
                users.Add(new User
                {
                    Id = reader.GetInt32("Id"),
                    Username = reader.GetString("Username"),
                    Email = reader.GetString("Email")
                });
            }
            
            return users;
        }
    }

    /// <summary>
    /// ❌ VULNERABLE WEB FORM HANDLER - Educational Example Only
    /// Contains intentional XSS vulnerabilities for learning purposes
    /// Students should use Copilot to identify and fix these security issues
    /// </summary>
    public class VulnerableFormHandler
    {
        /// <summary>
        /// ❌ VULNERABLE: XSS via unescaped output
        /// Copilot Exercise: Add proper HTML encoding to prevent script injection
        /// Attack Vector: comment = "<script>alert('XSS Attack!')</script>"
        /// </summary>
        public string DisplayComment(string username, string comment)
        {
            // 🚨 SECURITY VULNERABILITY: Direct HTML output without encoding
            return $@"
                <div class='comment'>
                    <strong>{username} says:</strong>
                    <p>{comment}</p>
                    <small>Posted on {DateTime.Now:yyyy-MM-dd}</small>
                </div>";
        }

        /// <summary>
        /// ❌ VULNERABLE: JavaScript injection in attribute
        /// Copilot Exercise: Fix the attribute injection vulnerability
        /// Attack Vector: userTitle = "Admin\" onmouseover=\"alert('XSS')\""
        /// </summary>
        public string CreateUserProfile(string username, string userTitle, string bio)
        {
            // 🚨 SECURITY VULNERABILITY: Unescaped attributes and content
            return $@"
                <div class='user-profile' title='{userTitle}'>
                    <h2>{username}'s Profile</h2>
                    <div class='bio'>{bio}</div>
                    <script>
                        var currentUser = '{username}'; // Vulnerable to script breaking
                        var userBio = '{bio}'; // Another injection point
                    </script>
                </div>";
        }

        /// <summary>
        /// ❌ VULNERABLE: URL injection and open redirect
        /// Copilot Exercise: Validate and sanitize the redirect URL
        /// Attack Vector: redirectUrl = "javascript:alert('XSS')" or "http://evil.com"
        /// </summary>
        public string CreateRedirectLink(string redirectUrl, string linkText)
        {
            // 🚨 SECURITY VULNERABILITY: Unvalidated redirect
            return $@"<a href='{redirectUrl}' onclick='window.location.href=""{redirectUrl}""'>{linkText}</a>";
        }

        /// <summary>
        /// ❌ VULNERABLE: Unsafe deserialization placeholder
        /// Copilot Exercise: Identify risks of deserializing untrusted data
        /// Note: This is a conceptual example for discussion
        /// </summary>
        public void ProcessUserData(string serializedData)
        {
            // 🚨 SECURITY VULNERABILITY: Potential deserialization attack
            // In real scenarios, this could lead to remote code execution
            try
            {
                // Placeholder for unsafe deserialization
                // var userData = JsonSerializer.Deserialize<dynamic>(serializedData);
                Console.WriteLine($"Processing data: {serializedData}");
            }
            catch (Exception ex)
            {
                // 🚨 VULNERABILITY: Information disclosure in error messages
                throw new Exception($"Deserialization failed with data: {serializedData}. Error: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// User model for the examples above
    /// </summary>
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string PasswordHash { get; set; } = "";
    }

    /// <summary>
    /// ❌ VULNERABLE FILE HANDLER - Educational Example
    /// Contains path traversal and file upload vulnerabilities
    /// </summary>
    public class VulnerableFileHandler
    {
        private readonly string _uploadDirectory = @"C:\SafeVault\Uploads\";

        /// <summary>
        /// ❌ VULNERABLE: Path traversal attack
        /// Copilot Exercise: Fix directory traversal vulnerability
        /// Attack Vector: filename = "../../Windows/System32/config/SAM"
        /// </summary>
        public string ReadUserFile(string filename)
        {
            // 🚨 SECURITY VULNERABILITY: Path traversal
            string filePath = Path.Combine(_uploadDirectory, filename);
            
            if (File.Exists(filePath))
            {
                return File.ReadAllText(filePath);
            }
            
            throw new FileNotFoundException($"File not found: {filename}");
        }

        /// <summary>
        /// ❌ VULNERABLE: Unrestricted file upload
        /// Copilot Exercise: Add file type validation and size limits
        /// Attack Vector: Upload executable files or oversized files
        /// </summary>
        public void SaveUploadedFile(string filename, byte[] fileContent)
        {
            // 🚨 SECURITY VULNERABILITY: No file type or size validation
            string filePath = Path.Combine(_uploadDirectory, filename);
            
            File.WriteAllBytes(filePath, fileContent);
            Console.WriteLine($"File saved: {filePath}");
        }
    }
}

/*
 * SECURITY TESTING INSTRUCTIONS FOR STUDENTS:
 * 
 * 1. Use Copilot to analyze each function above
 * 2. Ask Copilot: "What security vulnerabilities do you see in this code?"
 * 3. Request fixes: "How can I make this code secure against injection attacks?"
 * 4. Generate test cases: "Create test cases to verify these fixes work"
 * 
 * EXPECTED COPILOT SUGGESTIONS:
 * - Replace string concatenation with parameterized queries
 * - Add HTML encoding for all output
 * - Validate and sanitize all user inputs  
 * - Implement proper error handling
 * - Add file type and size validation
 * - Use allow-lists instead of deny-lists
 * 
 * REMEMBER: These are intentionally vulnerable examples for educational purposes only!
 */
