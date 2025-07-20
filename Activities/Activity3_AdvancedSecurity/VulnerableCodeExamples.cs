using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Web;

namespace SafeVault.Activity3.Vulnerable
{
    /// <summary>
    /// ❌ VULNERABLE ADVANCED SECURITY EXAMPLES - DO NOT USE IN PRODUCTION
    /// This class demonstrates advanced security vulnerabilities for educational purposes
    /// </summary>
    public class VulnerableAdvancedSecurityExamples
    {
        #region Cross-Site Scripting (XSS) Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: Direct output without encoding allows XSS
        /// </summary>
        public static string DisplayUserComment_Vulnerable(string username, string comment)
        {
            // ❌ VULNERABLE: No HTML encoding
            return $"<div class='comment'><b>{username}</b> says: {comment}</div>";
            
            // Attack vector: comment = "<script>alert('XSS')</script>"
            // Result: JavaScript execution in browser
        }

        /// <summary>
        /// ❌ VULNERABLE: Stored XSS through database content
        /// </summary>
        public static string RenderUserProfile_Vulnerable(UserProfile profile)
        {
            // ❌ VULNERABLE: Direct rendering of user-controlled data
            StringBuilder html = new StringBuilder();
            html.AppendLine($"<h2>Profile: {profile.DisplayName}</h2>");
            html.AppendLine($"<p>Bio: {profile.Biography}</p>");
            html.AppendLine($"<p>Website: <a href='{profile.Website}'>{profile.Website}</a></p>");
            html.AppendLine($"<script>var userId = '{profile.UserId}';</script>");
            
            return html.ToString();
            
            // Attack vectors:
            // DisplayName: "<script>alert('Stored XSS')</script>"
            // Website: "javascript:alert('XSS')"
            // Biography: "<img src=x onerror=alert('XSS')>"
        }

        /// <summary>
        /// ❌ VULNERABLE: DOM-based XSS through URL parameters
        /// </summary>
        public static string GenerateSearchResults_Vulnerable(string searchTerm)
        {
            // ❌ VULNERABLE: Reflecting user input directly into JavaScript
            return $@"
                <script>
                    document.getElementById('searchTerm').innerHTML = 'Results for: {searchTerm}';
                    var query = '{searchTerm}';
                    performSearch(query);
                </script>";
            
            // Attack vector: searchTerm = "'; alert('DOM XSS'); //"
        }

        #endregion

        #region Cross-Site Request Forgery (CSRF) Vulnerabilities

        /// <summary>
        /// ❌ VULNERABLE: No CSRF protection on sensitive operations
        /// </summary>
        public class VulnerableCSRFController
        {
            public static string ProcessPasswordChange_Vulnerable(HttpRequest request)
            {
                // ❌ VULNERABLE: No CSRF token validation
                string username = request.Params["username"];
                string newPassword = request.Params["newPassword"];
                
                // ❌ Direct processing without CSRF protection
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(newPassword))
                {
                    // Change password immediately - no additional verification!
                    ChangeUserPassword(username, newPassword);
                    return "Password changed successfully";
                }
                
                return "Invalid request";
                
                // Attack scenario: Victim visits malicious site with:
                // <form action="http://victim-site.com/changepassword" method="POST">
                //   <input name="username" value="victim@email.com">
                //   <input name="newPassword" value="hacker123">
                // </form>
                // <script>document.forms[0].submit();</script>
            }

            public static string DeleteUserAccount_Vulnerable(HttpRequest request)
            {
                // ❌ VULNERABLE: Critical action with no CSRF protection
                string userId = request.Params["userId"];
                
                if (!string.IsNullOrEmpty(userId))
                {
                    DeleteAccount(userId);
                    return "Account deleted";
                }
                
                return "Invalid request";
            }

            public static string TransferFunds_Vulnerable(HttpRequest request)
            {
                // ❌ VULNERABLE: Financial transaction without CSRF protection
                string fromAccount = request.Params["from"];
                string toAccount = request.Params["to"];
                string amount = request.Params["amount"];
                
                ProcessTransfer(fromAccount, toAccount, decimal.Parse(amount));
                return "Transfer completed";
            }
        }

        #endregion

        #region Insecure Direct Object References (IDOR)

        /// <summary>
        /// ❌ VULNERABLE: Direct access to objects without authorization
        /// </summary>
        public static class VulnerableDocumentAccess
        {
            public static Document GetDocument_Vulnerable(string documentId)
            {
                // ❌ VULNERABLE: No ownership or permission check
                return LoadDocumentFromDatabase(documentId);
                
                // Attack: User changes URL from /doc/123 to /doc/456
                // to access other users' documents
            }

            public static void DeleteDocument_Vulnerable(string documentId, string currentUserId)
            {
                // ❌ VULNERABLE: Only checks if user is authenticated, not authorized
                if (!string.IsNullOrEmpty(currentUserId))
                {
                    DeleteDocumentFromDatabase(documentId);
                }
                
                // Any authenticated user can delete any document!
            }

            public static List<Document> GetUserDocuments_Vulnerable(string targetUserId)
            {
                // ❌ VULNERABLE: No check if requesting user can access target user's docs
                return LoadUserDocuments(targetUserId);
                
                // Attack: /api/documents/user/999 reveals other user's documents
            }
        }

        #endregion

        #region Security Misconfiguration

        /// <summary>
        /// ❌ VULNERABLE: Insecure file upload handling
        /// </summary>
        public static class VulnerableFileUpload
        {
            public static string UploadFile_Vulnerable(HttpPostedFile file, string uploadPath)
            {
                // ❌ VULNERABLE: No file type validation
                // ❌ VULNERABLE: No file size limits
                // ❌ VULNERABLE: Executable files allowed
                
                string fileName = file.FileName; // ❌ User-controlled filename
                string fullPath = Path.Combine(uploadPath, fileName);
                
                // ❌ VULNERABLE: Files saved with original names
                file.SaveAs(fullPath);
                
                return $"File uploaded: {fileName}";
                
                // Attack vectors:
                // 1. Upload .asp, .php, .exe files
                // 2. Path traversal: ../../../windows/system32/evil.exe
                // 3. Overwrite existing files
                // 4. Denial of Service with huge files
            }

            public static byte[] DownloadFile_Vulnerable(string filePath)
            {
                // ❌ VULNERABLE: No path validation - path traversal possible
                return File.ReadAllBytes(filePath);
                
                // Attack: filePath = "../../../../etc/passwd"
                // or: filePath = "../../web.config"
            }
        }

        /// <summary>
        /// ❌ VULNERABLE: Information disclosure through errors
        /// </summary>
        public static class VulnerableErrorHandling
        {
            public static string ProcessUserData_Vulnerable(string userData)
            {
                try
                {
                    // Some processing that might fail
                    ProcessData(userData);
                    return "Success";
                }
                catch (Exception ex)
                {
                    // ❌ VULNERABLE: Exposing full exception details
                    return $@"
                        Error occurred: {ex.Message}
                        Stack trace: {ex.StackTrace}
                        Inner exception: {ex.InnerException?.Message}
                        Source: {ex.Source}
                        Data: {string.Join(", ", ex.Data.Keys)}";
                    
                    // This reveals:
                    // - Application structure
                    // - Database schema details
                    // - File paths
                    // - Technology stack information
                }
            }

            public static void LogSensitiveInfo_Vulnerable(string username, string operation, object sensitiveData)
            {
                // ❌ VULNERABLE: Logging sensitive information
                string logMessage = $@"
                    [{DateTime.Now}] User: {username}
                    Operation: {operation}
                    Sensitive Data: {sensitiveData}
                    Session Info: {HttpContext.Current?.Session?.SessionID}
                    Request Details: {HttpContext.Current?.Request?.Url}";
                
                // ❌ Writing to plain text log files
                File.AppendAllText("C:\\Logs\\application.log", logMessage);
                
                // ❌ Also logging to console (visible in production)
                Console.WriteLine(logMessage);
            }
        }

        #endregion

        #region Insecure Cryptographic Storage

        /// <summary>
        /// ❌ VULNERABLE: Weak encryption implementations
        /// </summary>
        public static class VulnerableCryptography
        {
            // ❌ VULNERABLE: Hardcoded encryption key
            private static readonly byte[] WEAK_KEY = Encoding.UTF8.GetBytes("MySecretKey12345");

            public static string EncryptData_Vulnerable(string plaintext)
            {
                // ❌ VULNERABLE: Using outdated DES encryption
                using (var des = System.Security.Cryptography.DES.Create())
                {
                    des.Key = WEAK_KEY.Take(8).ToArray(); // DES only uses 8 bytes
                    des.Mode = System.Security.Cryptography.CipherMode.ECB; // ❌ Insecure mode
                    
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                    using (var encryptor = des.CreateEncryptor())
                    {
                        byte[] cipherBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
                        return Convert.ToBase64String(cipherBytes);
                    }
                }
                
                // Issues:
                // 1. DES is cryptographically broken
                // 2. Hardcoded key
                // 3. ECB mode reveals patterns
                // 4. No IV (Initialization Vector)
            }

            public static string HashPassword_Vulnerable(string password)
            {
                // ❌ VULNERABLE: Using MD5 without salt
                using (var md5 = System.Security.Cryptography.MD5.Create())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(password);
                    byte[] hashBytes = md5.ComputeHash(inputBytes);
                    return BitConverter.ToString(hashBytes).Replace("-", "");
                }
                
                // Issues:
                // 1. MD5 is cryptographically broken
                // 2. No salt - vulnerable to rainbow tables
                // 3. Fast hashing - vulnerable to brute force
            }

            public static string GenerateRandomToken_Vulnerable()
            {
                // ❌ VULNERABLE: Using weak random number generator
                Random rand = new Random(); // Not cryptographically secure!
                
                StringBuilder token = new StringBuilder();
                for (int i = 0; i < 16; i++)
                {
                    token.Append(rand.Next(0, 10)); // Only digits, very limited entropy
                }
                
                return token.ToString();
                
                // Issues:
                // 1. Predictable random number generator
                // 2. Low entropy (only digits)
                // 3. Seeded with current time - predictable
            }
        }

        #endregion

        #region Insufficient Security Headers

        /// <summary>
        /// ❌ VULNERABLE: Missing security headers
        /// </summary>
        public static class VulnerableSecurityHeaders
        {
            public static void SetInsecureHeaders_Vulnerable(HttpResponse response)
            {
                // ❌ Missing critical security headers:
                
                // ❌ No Content Security Policy
                // Should have: Content-Security-Policy: default-src 'self'
                
                // ❌ No X-Frame-Options  
                // Should have: X-Frame-Options: DENY
                
                // ❌ No X-Content-Type-Options
                // Should have: X-Content-Type-Options: nosniff
                
                // ❌ No X-XSS-Protection
                // Should have: X-XSS-Protection: 1; mode=block
                
                // ❌ No Strict-Transport-Security
                // Should have: Strict-Transport-Security: max-age=31536000; includeSubDomains
                
                // ❌ Exposing server information
                response.Headers.Add("Server", "Apache/2.4.41 (Ubuntu) PHP/7.4.3");
                response.Headers.Add("X-Powered-By", "PHP/7.4.3");
                
                // ❌ Allowing all origins for CORS
                response.Headers.Add("Access-Control-Allow-Origin", "*");
                response.Headers.Add("Access-Control-Allow-Methods", "*");
                response.Headers.Add("Access-Control-Allow-Headers", "*");
                
                // ❌ Weak referrer policy
                response.Headers.Add("Referrer-Policy", "unsafe-url");
            }

            public static void ConfigureInsecureSession_Vulnerable(HttpResponse response, string sessionId)
            {
                // ❌ VULNERABLE: Insecure session cookie
                var sessionCookie = new HttpCookie("SESSIONID", sessionId)
                {
                    // ❌ Missing Secure flag - cookie sent over HTTP
                    Secure = false,
                    
                    // ❌ Missing HttpOnly flag - accessible to JavaScript
                    HttpOnly = false,
                    
                    // ❌ Missing SameSite protection
                    SameSite = SameSiteMode.None,
                    
                    // ❌ No expiration - persistent cookie
                    Expires = DateTime.MaxValue,
                    
                    // ❌ Overly broad domain
                    Domain = ".example.com",
                    
                    // ❌ Root path access
                    Path = "/"
                };
                
                response.Cookies.Add(sessionCookie);
            }
        }

        #endregion

        #region Injection Flaws (Beyond SQL)

        /// <summary>
        /// ❌ VULNERABLE: Command injection
        /// </summary>
        public static class VulnerableCommandExecution
        {
            public static string ExecuteSystemCommand_Vulnerable(string userInput)
            {
                // ❌ VULNERABLE: Direct command execution with user input
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c dir {userInput}", // User input directly in command
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                return output;
                
                // Attack vector: userInput = "C:\\ & del /Q /S C:\\*.*"
                // This would attempt to delete all files on C drive!
            }

            public static string ProcessLogFile_Vulnerable(string filename)
            {
                // ❌ VULNERABLE: LDAP injection
                string ldapFilter = $"(&(objectClass=user)(sAMAccountName={filename}))";
                
                // Attack: filename = "*)(uid=*))(|(uid=*"
                // This could bypass authentication or extract all users
                
                return SearchLDAP(ldapFilter);
            }

            public static void ProcessXMLInput_Vulnerable(string xmlInput)
            {
                // ❌ VULNERABLE: XXE (XML External Entity) injection
                var xmlDoc = new System.Xml.XmlDocument();
                xmlDoc.LoadXml(xmlInput); // No restrictions on external entities
                
                // Attack XML:
                // <?xml version="1.0"?>
                // <!DOCTYPE root [
                //   <!ENTITY xxe SYSTEM "file:///etc/passwd">
                // ]>
                // <root>&xxe;</root>
                
                ProcessXMLDocument(xmlDoc);
            }
        }

        #endregion

        #region Supporting Methods (Placeholders)

        private static void ChangeUserPassword(string username, string newPassword) { }
        private static void DeleteAccount(string userId) { }
        private static void ProcessTransfer(string from, string to, decimal amount) { }
        private static Document LoadDocumentFromDatabase(string id) => new Document { Id = id };
        private static void DeleteDocumentFromDatabase(string id) { }
        private static List<Document> LoadUserDocuments(string userId) => new List<Document>();
        private static void ProcessData(string data) { }
        private static string SearchLDAP(string filter) => "LDAP Results";
        private static void ProcessXMLDocument(System.Xml.XmlDocument doc) { }

        #endregion
    }

    #region Supporting Classes

    public class UserProfile
    {
        public string UserId { get; set; }
        public string DisplayName { get; set; }
        public string Biography { get; set; }
        public string Website { get; set; }
    }

    public class Document
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public string OwnerId { get; set; }
    }

    #endregion
}
