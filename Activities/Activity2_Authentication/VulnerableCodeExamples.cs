using System;
using System.Collections.Generic;
using System.Web;

namespace SafeVault.Activity2.Vulnerable
{
    /// <summary>
    /// ❌ VULNERABLE AUTHENTICATION EXAMPLES - DO NOT USE IN PRODUCTION
    /// This class demonstrates common authentication vulnerabilities for educational purposes
    /// </summary>
    public class VulnerableAuthenticationExamples
    {
        // ❌ VULNERABLE: Hardcoded credentials
        private const string ADMIN_USERNAME = "admin";
        private const string ADMIN_PASSWORD = "password123";

        #region Session Management Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Insecure session management
        /// </summary>
        public class InsecureSessionManager
        {
            // ❌ VULNERABLE: Predictable session IDs
            private static int sessionCounter = 1000;
            private static Dictionary<string, UserSession> sessions = new Dictionary<string, UserSession>();

            public static string CreateSession_Vulnerable(string username)
            {
                // ❌ VULNERABLE: Sequential, predictable session ID
                string sessionId = (sessionCounter++).ToString();
                
                sessions[sessionId] = new UserSession
                {
                    Username = username,
                    CreatedAt = DateTime.Now,
                    // ❌ VULNERABLE: No expiration time
                    LastActivity = DateTime.Now,
                    // ❌ VULNERABLE: No security flags
                    IsSecure = false,
                    HttpOnly = false
                };

                return sessionId;
            }

            public static bool ValidateSession_Vulnerable(string sessionId)
            {
                // ❌ VULNERABLE: No session expiration check
                // ❌ VULNERABLE: No activity timeout
                return sessions.ContainsKey(sessionId);
            }

            public static void StoreSessionInCookie_Vulnerable(HttpResponse response, string sessionId)
            {
                // ❌ VULNERABLE: Insecure cookie settings
                var cookie = new HttpCookie("SessionID", sessionId)
                {
                    // ❌ Missing Secure flag
                    Secure = false,
                    // ❌ Missing HttpOnly flag  
                    HttpOnly = false,
                    // ❌ No SameSite protection
                    SameSite = SameSiteMode.None,
                    // ❌ No expiration
                    Expires = DateTime.MaxValue
                };
                
                response.Cookies.Add(cookie);
            }
        }

        #endregion

        #region Password Management Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Weak password validation
        /// </summary>
        public static bool ValidatePassword_Vulnerable(string password)
        {
            // ❌ VULNERABLE: Minimal password requirements
            return password.Length >= 4; // Way too weak!
        }

        /// <summary>
        /// ❌ VULNERABLE: Plain text password storage
        /// </summary>
        public static void StorePassword_Vulnerable(string username, string password)
        {
            // ❌ VULNERABLE: Storing passwords in plain text
            using (var writer = new System.IO.StreamWriter("passwords.txt", true))
            {
                writer.WriteLine($"{username}:{password}");
            }
        }

        /// <summary>
        /// ❌ VULNERABLE: Weak password hashing
        /// </summary>
        public static string HashPassword_Vulnerable(string password)
        {
            // ❌ VULNERABLE: Using weak MD5 without salt
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return Convert.ToHexString(hashBytes);
            }
        }

        #endregion

        #region Authentication Bypass Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Authentication bypass through parameter manipulation
        /// </summary>
        public static bool AuthenticateUser_Vulnerable(string username, string password, bool isAdmin = false)
        {
            // ❌ VULNERABLE: Client-controlled admin flag
            if (isAdmin)
            {
                return true; // Anyone can set isAdmin=true!
            }

            // ❌ VULNERABLE: Weak authentication logic
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return false;
            }

            // ❌ VULNERABLE: Hardcoded credentials check
            return username == ADMIN_USERNAME && password == ADMIN_PASSWORD;
        }

        /// <summary>
        /// ❌ VULNERABLE: SQL injection in authentication
        /// </summary>
        public static bool AuthenticateWithDatabase_Vulnerable(string username, string password)
        {
            // ❌ VULNERABLE: Direct string concatenation
            string query = $"SELECT COUNT(*) FROM Users WHERE Username = '{username}' AND Password = '{password}'";
            
            // ❌ Attack vector: username = "admin' OR '1'='1' --"
            // This would bypass authentication completely
            
            // Simulated vulnerable behavior
            if (username.Contains("' OR '1'='1'"))
            {
                return true; // Authentication bypassed!
            }

            return false;
        }

        #endregion

        #region Multi-Factor Authentication Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Weak MFA implementation
        /// </summary>
        public class VulnerableMFAManager
        {
            // ❌ VULNERABLE: Predictable MFA codes
            public static string GenerateMFACode_Vulnerable()
            {
                // ❌ VULNERABLE: Using timestamp for "random" code
                var timestamp = DateTime.Now.Ticks.ToString();
                return timestamp.Substring(timestamp.Length - 6); // Last 6 digits
            }

            /// <summary>
            /// ❌ VULNERABLE: MFA bypass through timing
            /// </summary>
            public static bool ValidateMFACode_Vulnerable(string userCode, string actualCode)
            {
                // ❌ VULNERABLE: Early return reveals information through timing
                for (int i = 0; i < Math.Min(userCode.Length, actualCode.Length); i++)
                {
                    if (userCode[i] != actualCode[i])
                    {
                        return false; // Timing attack possible!
                    }
                }
                return userCode.Length == actualCode.Length;
            }

            /// <summary>
            /// ❌ VULNERABLE: MFA state stored client-side
            /// </summary>
            public static void StoreMFAState_Vulnerable(HttpResponse response, bool mfaPassed)
            {
                // ❌ VULNERABLE: Storing MFA state in client cookie
                var cookie = new HttpCookie("MFA_Verified", mfaPassed.ToString())
                {
                    Secure = false,
                    HttpOnly = false
                };
                response.Cookies.Add(cookie);
            }
        }

        #endregion

        #region Authorization Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Insecure direct object reference
        /// </summary>
        public static UserProfile GetUserProfile_Vulnerable(string sessionId, int userId)
        {
            // ❌ VULNERABLE: No authorization check - any authenticated user can access any profile
            if (InsecureSessionManager.ValidateSession_Vulnerable(sessionId))
            {
                return LoadUserProfile(userId); // Direct access without permission check!
            }
            return null;
        }

        /// <summary>
        /// ❌ VULNERABLE: Role-based access control bypass
        /// </summary>
        public static bool HasAdminAccess_Vulnerable(string userRole)
        {
            // ❌ VULNERABLE: Case-sensitive comparison allows bypass
            // Attack: userRole = "ADMIN" (uppercase) bypasses "admin" check
            return userRole == "admin"; // Should be case-insensitive!
        }

        /// <summary>
        /// ❌ VULNERABLE: Privilege escalation through parameter pollution
        /// </summary>
        public static void UpdateUserRole_Vulnerable(Dictionary<string, string> parameters)
        {
            // ❌ VULNERABLE: No validation of who can change roles
            if (parameters.ContainsKey("userId") && parameters.ContainsKey("newRole"))
            {
                var userId = parameters["userId"];
                var newRole = parameters["newRole"];
                
                // ❌ VULNERABLE: Any user can potentially escalate privileges
                UpdateUserRoleInDatabase(userId, newRole);
            }
        }

        #endregion

        #region Account Management Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: No account lockout mechanism
        /// </summary>
        public static class VulnerableAccountManager
        {
            private static Dictionary<string, int> failedAttempts = new Dictionary<string, int>();

            public static bool CheckCredentials_Vulnerable(string username, string password)
            {
                // ❌ VULNERABLE: No rate limiting or account lockout
                // Allows unlimited brute force attempts
                
                bool isValid = (username == ADMIN_USERNAME && password == ADMIN_PASSWORD);
                
                if (!isValid)
                {
                    // ❌ Count failed attempts but don't act on them
                    failedAttempts[username] = failedAttempts.GetValueOrDefault(username, 0) + 1;
                    
                    // ❌ VULNERABLE: Log shows actual attempt counts (information leakage)
                    Console.WriteLine($"Failed login for {username}. Total attempts: {failedAttempts[username]}");
                }
                else
                {
                    failedAttempts.Remove(username);
                }

                return isValid;
            }
        }

        /// <summary>
        /// ❌ VULNERABLE: Insecure password reset
        /// </summary>
        public static class VulnerablePasswordReset
        {
            public static string GenerateResetToken_Vulnerable(string email)
            {
                // ❌ VULNERABLE: Predictable reset tokens
                var timestamp = DateTime.Now.Ticks;
                var emailHash = email.GetHashCode();
                
                // ❌ Easily guessable token
                return $"{timestamp}{emailHash}";
            }

            public static bool ValidateResetToken_Vulnerable(string token, string email)
            {
                // ❌ VULNERABLE: No expiration check
                // ❌ VULNERABLE: Tokens never invalidated
                return token.EndsWith(email.GetHashCode().ToString());
            }
        }

        #endregion

        #region Supporting Methods

        private static UserProfile LoadUserProfile(int userId)
        {
            return new UserProfile { UserId = userId, Username = $"User{userId}" };
        }

        private static void UpdateUserRoleInDatabase(string userId, string newRole)
        {
            // Simulated database update
            Console.WriteLine($"Role updated for user {userId}: {newRole}");
        }

        #endregion
    }

    #region Supporting Classes

    public class UserSession
    {
        public string Username { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public bool IsSecure { get; set; }
        public bool HttpOnly { get; set; }
    }

    public class UserProfile
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
    }

    #endregion
}
