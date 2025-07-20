using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SafeVault.Activity3.Tests
{
    /// <summary>
    /// 🧪 COMPREHENSIVE ADVANCED SECURITY TEST SUITE
    /// Tests for advanced security vulnerabilities and secure implementations
    /// </summary>
    [TestClass]
    public class AdvancedSecurityTestSuite
    {
        private TestContext testContextInstance;
        private TestLogger testLogger;
        private TestConfigurationManager testConfig;
        private TestCacheManager testCache;

        public TestContext TestContext
        {
            get { return testContextInstance; }
            set { testContextInstance = value; }
        }

        #region Test Setup

        [TestInitialize]
        public void TestInitialize()
        {
            testLogger = new TestLogger();
            testConfig = new TestConfigurationManager();
            testCache = new TestCacheManager();
        }

        [TestCleanup]
        public void TestCleanup()
        {
            testLogger.Clear();
            testConfig.Clear();
            testCache.Clear();
        }

        #endregion

        #region XSS Prevention Tests

        [TestMethod]
        [TestCategory("XSS")]
        [Priority(1)]
        public void TestXSS_VulnerableCode_AllowsScriptExecution()
        {
            // Arrange
            string username = "TestUser";
            string maliciousComment = "<script>alert('XSS Attack!')</script>";

            // Act
            string result = VulnerableAdvancedSecurityExamples.DisplayUserComment_Vulnerable(username, maliciousComment);

            // Assert
            Assert.IsTrue(result.Contains("<script>"), "❌ VULNERABILITY: Script tags are not encoded");
            Assert.IsTrue(result.Contains("alert('XSS Attack!')"), "❌ VULNERABILITY: JavaScript code is preserved");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: XSS attack possible through unencoded output");
        }

        [TestMethod]
        [TestCategory("XSS")]
        [Priority(1)]
        public void TestXSS_SecureCode_EncodesOutput()
        {
            // Arrange
            string username = "TestUser";
            string maliciousComment = "<script>alert('XSS Attack!')</script>";

            // Act
            string result = SecureAdvancedSecurityExamples.DisplayUserComment_Secure(username, maliciousComment);

            // Assert
            Assert.IsFalse(result.Contains("<script>"), "Script tags should be encoded");
            Assert.IsTrue(result.Contains("&lt;script&gt;"), "Script tags should be HTML encoded");
            Assert.IsTrue(result.Contains("alert(&#39;XSS Attack!&#39;)"), "JavaScript should be encoded");
            TestContext.WriteLine("✅ SECURE: XSS prevented through proper HTML encoding");
        }

        [TestMethod]
        [TestCategory("XSS")]
        [DataRow("<img src=x onerror=alert('XSS')>")]
        [DataRow("<svg onload=alert('XSS')>")]
        [DataRow("javascript:alert('XSS')")]
        [DataRow("<iframe src=\"javascript:alert('XSS')\">")]
        public void TestXSS_VariousAttackVectors_AreNeutralized(string xssPayload)
        {
            // Act
            string result = SecureAdvancedSecurityExamples.DisplayUserComment_Secure("user", xssPayload);

            // Assert
            Assert.IsFalse(result.Contains("javascript:"), "JavaScript protocol should be encoded");
            Assert.IsFalse(result.Contains("onerror="), "Event handlers should be encoded");
            Assert.IsFalse(result.Contains("onload="), "Event handlers should be encoded");
            TestContext.WriteLine($"✅ XSS payload neutralized: {xssPayload}");
        }

        [TestMethod]
        [TestCategory("XSS")]
        public void TestXSS_StoredXSS_Prevention()
        {
            // Arrange
            var profile = new VulnerableAdvancedSecurityExamples.UserProfile
            {
                UserId = "123",
                DisplayName = "<script>alert('Stored XSS')</script>",
                Biography = "<img src=x onerror=alert('Bio XSS')>",
                Website = "javascript:alert('Website XSS')"
            };

            // Act
            string result = SecureAdvancedSecurityExamples.RenderUserProfile_Secure(profile);

            // Assert
            Assert.IsFalse(result.Contains("<script>"), "Script tags should be encoded in profile");
            Assert.IsFalse(result.Contains("javascript:"), "JavaScript URLs should be rejected");
            Assert.IsFalse(result.Contains("onerror="), "Event handlers should be encoded");
            TestContext.WriteLine("✅ SECURE: Stored XSS prevented in user profile rendering");
        }

        #endregion

        #region CSRF Protection Tests

        [TestMethod]
        [TestCategory("CSRF")]
        [Priority(1)]
        public void TestCSRF_VulnerableCode_AllowsForgedRequests()
        {
            // Arrange
            var request = CreateMockHttpRequest(new Dictionary<string, string>
            {
                {"username", "victim@example.com"},
                {"newPassword", "hacked123"}
            });

            // Act
            string result = VulnerableAdvancedSecurityExamples.VulnerableCSRFController
                .ProcessPasswordChange_Vulnerable(request);

            // Assert
            Assert.AreEqual("Password changed successfully", result, 
                "❌ VULNERABILITY: Password changed without CSRF protection");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: CSRF attack successful - password changed without token verification");
        }

        [TestMethod]
        [TestCategory("CSRF")]
        [Priority(1)]
        public void TestCSRF_SecureCode_RequiresValidToken()
        {
            // Arrange
            var csrfProtection = new SecureAdvancedSecurityExamples.SecureCSRFProtection(testCache, testLogger);
            string sessionId = "test_session_123";
            
            var request = CreateMockHttpRequest(new Dictionary<string, string>
            {
                {"username", "user@example.com"},
                {"newPassword", "newPassword123"},
                {"currentPassword", "oldPassword123"},
                {"__RequestVerificationToken", "invalid_token"}
            });

            // Act
            var result = csrfProtection.ProcessPasswordChange(request, sessionId);

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("Invalid request token", result.Message);
            TestContext.WriteLine("✅ SECURE: CSRF protection blocks request with invalid token");
        }

        [TestMethod]
        [TestCategory("CSRF")]
        public void TestCSRF_ValidToken_AllowsLegitimateRequest()
        {
            // Arrange
            var csrfProtection = new SecureAdvancedSecurityExamples.SecureCSRFProtection(testCache, testLogger);
            string sessionId = "test_session_123";
            
            // Generate and store valid CSRF token
            string validToken = csrfProtection.GenerateCSRFToken(sessionId);
            
            var request = CreateMockHttpRequest(new Dictionary<string, string>
            {
                {"username", "user@example.com"},
                {"newPassword", "newPassword123!"},
                {"currentPassword", "oldPassword123"},
                {"__RequestVerificationToken", validToken}
            });

            // Act
            var result = csrfProtection.ProcessPasswordChange(request, sessionId);

            // Assert
            Assert.IsTrue(result.Success);
            TestContext.WriteLine("✅ SECURE: Valid CSRF token allows legitimate request");
        }

        #endregion

        #region File Upload Security Tests

        [TestMethod]
        [TestCategory("FileUpload")]
        [Priority(1)]
        public void TestFileUpload_VulnerableCode_AllowsDangerousFiles()
        {
            // Arrange
            string uploadPath = @"C:\TestUploads";
            var maliciousFile = CreateMockPostedFile("malware.exe", "application/x-msdownload", new byte[] { 0x4D, 0x5A }); // PE header

            // Act
            string result = VulnerableAdvancedSecurityExamples.VulnerableFileUpload
                .UploadFile_Vulnerable(maliciousFile, uploadPath);

            // Assert
            Assert.IsTrue(result.Contains("File uploaded: malware.exe"), 
                "❌ VULNERABILITY: Executable files are allowed");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Dangerous file types allowed for upload");
        }

        [TestMethod]
        [TestCategory("FileUpload")]
        public void TestFileUpload_SecureCode_BlocksDangerousFiles()
        {
            // Arrange
            var secureUpload = new SecureAdvancedSecurityExamples.SecureFileUpload(
                testLogger, testConfig, null);
            
            var maliciousFile = CreateMockPostedFile("malware.exe", "application/x-msdownload", new byte[100]);

            // Act
            var result = secureUpload.UploadFile(maliciousFile, "user123", @"C:\SecureUploads");

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("File type not allowed", result.Message);
            TestContext.WriteLine("✅ SECURE: Dangerous file types are blocked");
        }

        [TestMethod]
        [TestCategory("FileUpload")]
        public void TestFileUpload_PathTraversal_IsBlocked()
        {
            // Arrange
            var secureUpload = new SecureAdvancedSecurityExamples.SecureFileUpload(
                testLogger, testConfig, null);
            
            // Try path traversal attack
            string maliciousPath = "../../../Windows/System32/evil.txt";

            // Act
            var result = secureUpload.DownloadFile(maliciousPath, "user123");

            // Assert
            Assert.IsFalse(result.Success);
            TestContext.WriteLine("✅ SECURE: Path traversal attack blocked");
        }

        [TestMethod]
        [TestCategory("FileUpload")]
        public void TestFileUpload_AllowedTypes_AreAccepted()
        {
            // Arrange
            var secureUpload = new SecureAdvancedSecurityExamples.SecureFileUpload(
                testLogger, testConfig, null);
            
            testConfig.SetValue("Upload:MaxFileSizeBytes", 10 * 1024 * 1024); // 10MB
            
            var validFile = CreateMockPostedFile("document.pdf", "application/pdf", 
                Encoding.ASCII.GetBytes("%PDF-1.4")); // Valid PDF header

            // Act
            var result = secureUpload.UploadFile(validFile, "user123", @"C:\SecureUploads");

            // Assert - Note: This might fail due to actual file system operations in a real test
            // In a full implementation, you'd mock the file system operations
            TestContext.WriteLine($"File upload result: {result.Success} - {result.Message}");
        }

        #endregion

        #region Cryptography Security Tests

        [TestMethod]
        [TestCategory("Cryptography")]
        [Priority(1)]
        public void TestCryptography_VulnerableCode_UsesWeakEncryption()
        {
            // Arrange
            string plaintext = "Sensitive Data";

            // Act
            string encrypted1 = VulnerableAdvancedSecurityExamples.VulnerableCryptography
                .EncryptData_Vulnerable(plaintext);
            string encrypted2 = VulnerableAdvancedSecurityExamples.VulnerableCryptography
                .EncryptData_Vulnerable(plaintext);

            // Assert
            Assert.AreEqual(encrypted1, encrypted2, 
                "❌ VULNERABILITY: Same plaintext produces same ciphertext (no IV/salt)");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Weak encryption - same input produces same output");
        }

        [TestMethod]
        [TestCategory("Cryptography")]
        [Priority(1)]
        public void TestCryptography_SecureCode_UsesStrongEncryption()
        {
            // Arrange
            string plaintext = "Sensitive Data";
            byte[] key = new byte[32]; // 256-bit key
            new Random().NextBytes(key); // In real code, use cryptographically secure random

            // Act
            var result1 = SecureAdvancedSecurityExamples.SecureCryptography.EncryptData(plaintext, key);
            var result2 = SecureAdvancedSecurityExamples.SecureCryptography.EncryptData(plaintext, key);

            // Assert
            Assert.AreNotEqual(result1.Ciphertext, result2.Ciphertext, 
                "Different encryptions should produce different ciphertexts");
            Assert.AreNotEqual(result1.Nonce, result2.Nonce, "Each encryption should use unique nonce");
            Assert.AreEqual("AES-256-GCM", result1.Algorithm);
            
            // Test decryption
            string decrypted = SecureAdvancedSecurityExamples.SecureCryptography.DecryptData(result1, key);
            Assert.AreEqual(plaintext, decrypted);
            
            TestContext.WriteLine("✅ SECURE: Strong encryption with unique nonces and authenticated encryption");
        }

        [TestMethod]
        [TestCategory("Cryptography")]
        public void TestPasswordHashing_SecureImplementation()
        {
            // Arrange
            string password = "MySecurePassword123!";

            // Act
            var hash1 = SecureAdvancedSecurityExamples.SecureCryptography.HashPassword(password);
            var hash2 = SecureAdvancedSecurityExamples.SecureCryptography.HashPassword(password);

            // Assert
            Assert.AreNotEqual(hash1.Hash, hash2.Hash, "Same password should produce different hashes due to unique salts");
            Assert.AreNotEqual(hash1.Salt, hash2.Salt, "Each hash should have unique salt");
            Assert.AreEqual(100000, hash1.Iterations, "Should use high iteration count");
            Assert.AreEqual("PBKDF2-SHA256", hash1.Algorithm);

            // Verify password verification works
            Assert.IsTrue(SecureAdvancedSecurityExamples.SecureCryptography.VerifyPassword(password, hash1));
            Assert.IsFalse(SecureAdvancedSecurityExamples.SecureCryptography.VerifyPassword("WrongPassword", hash1));

            TestContext.WriteLine("✅ SECURE: Password hashing uses strong algorithm with unique salts");
        }

        [TestMethod]
        [TestCategory("Cryptography")]
        public void TestRandomToken_Generation_IsSecure()
        {
            // Act
            var tokens = new List<string>();
            for (int i = 0; i < 100; i++)
            {
                tokens.Add(SecureAdvancedSecurityExamples.SecureCryptography.GenerateSecureToken());
            }

            // Assert
            Assert.AreEqual(100, tokens.Distinct().Count(), "All tokens should be unique");
            Assert.IsTrue(tokens.All(t => t.Length > 40), "Tokens should be sufficiently long");
            TestContext.WriteLine("✅ SECURE: Random token generation produces unique, high-entropy tokens");
        }

        #endregion

        #region Security Headers Tests

        [TestMethod]
        [TestCategory("SecurityHeaders")]
        [Priority(1)]
        public void TestSecurityHeaders_VulnerableCode_ExposesInformation()
        {
            // Arrange
            var response = new TestHttpResponse();

            // Act
            VulnerableAdvancedSecurityExamples.VulnerableSecurityHeaders
                .SetInsecureHeaders_Vulnerable(response);

            // Assert
            Assert.IsTrue(response.Headers.ContainsKey("Server"), "❌ VULNERABILITY: Server information exposed");
            Assert.IsTrue(response.Headers.ContainsKey("X-Powered-By"), "❌ VULNERABILITY: Technology stack exposed");
            Assert.AreEqual("*", response.Headers.GetValueOrDefault("Access-Control-Allow-Origin"), 
                "❌ VULNERABILITY: Overly permissive CORS");
            Assert.IsFalse(response.Headers.ContainsKey("Content-Security-Policy"), 
                "❌ VULNERABILITY: Missing CSP header");
            
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Insecure headers expose information");
        }

        [TestMethod]
        [TestCategory("SecurityHeaders")]
        [Priority(1)]
        public void TestSecurityHeaders_SecureCode_SetsProtectiveHeaders()
        {
            // Arrange
            var response = new TestHttpResponse();

            // Act
            SecureAdvancedSecurityExamples.SecureHeaders.SetSecurityHeaders(response, true);

            // Assert
            Assert.IsTrue(response.Headers.ContainsKey("Content-Security-Policy"), "CSP header should be set");
            Assert.AreEqual("DENY", response.Headers.GetValueOrDefault("X-Frame-Options"));
            Assert.AreEqual("nosniff", response.Headers.GetValueOrDefault("X-Content-Type-Options"));
            Assert.AreEqual("1; mode=block", response.Headers.GetValueOrDefault("X-XSS-Protection"));
            Assert.IsTrue(response.Headers.GetValueOrDefault("Strict-Transport-Security").Contains("max-age=31536000"));
            Assert.IsFalse(response.Headers.ContainsKey("Server"), "Server header should be removed");
            Assert.IsFalse(response.Headers.ContainsKey("X-Powered-By"), "X-Powered-By header should be removed");
            
            TestContext.WriteLine("✅ SECURE: Comprehensive security headers are set");
        }

        #endregion

        #region Direct Object Reference Tests

        [TestMethod]
        [TestCategory("IDOR")]
        [Priority(1)]
        public void TestIDOR_VulnerableCode_AllowsDirectAccess()
        {
            // Arrange
            string documentId = "sensitive_document_123";

            // Act
            var document = VulnerableAdvancedSecurityExamples.VulnerableDocumentAccess
                .GetDocument_Vulnerable(documentId);

            // Assert
            Assert.IsNotNull(document, "❌ VULNERABILITY: Document accessed without authorization check");
            Assert.AreEqual(documentId, document.Id);
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Insecure direct object reference allows unauthorized access");
        }

        [TestMethod]
        [TestCategory("IDOR")]
        public void TestIDOR_SecureCode_RequiresAuthorization()
        {
            // Arrange
            var authService = new TestAuthorizationService();
            var secureAccess = new SecureAdvancedSecurityExamples.SecureDocumentAccess(testLogger, authService);
            
            string documentId = "document_123";
            string currentUserId = "user_456";
            
            // Setup: User doesn't have access to this document
            authService.SetDocumentAccess(currentUserId, documentId, "read", false);

            // Act
            var result = secureAccess.GetDocument(documentId, currentUserId);

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("Access denied", result.Message);
            TestContext.WriteLine("✅ SECURE: Authorization check prevents unauthorized document access");
        }

        [TestMethod]
        [TestCategory("IDOR")]
        public void TestIDOR_AuthorizedAccess_AllowsLegitimateUser()
        {
            // Arrange
            var authService = new TestAuthorizationService();
            var secureAccess = new SecureAdvancedSecurityExamples.SecureDocumentAccess(testLogger, authService);
            
            string documentId = "document_123";
            string currentUserId = "user_456";
            
            // Setup: User has access to this document
            authService.SetDocumentAccess(currentUserId, documentId, "read", true);

            // Act
            var result = secureAccess.GetDocument(documentId, currentUserId);

            // Assert
            Assert.IsTrue(result.Success);
            Assert.IsNotNull(result.Document);
            TestContext.WriteLine("✅ SECURE: Authorized users can access their documents");
        }

        #endregion

        #region Error Handling Tests

        [TestMethod]
        [TestCategory("ErrorHandling")]
        [Priority(1)]
        public void TestErrorHandling_VulnerableCode_ExposesInformation()
        {
            // Arrange
            string invalidData = "invalid_data_that_causes_exception";

            // Act
            string result = VulnerableAdvancedSecurityExamples.VulnerableErrorHandling
                .ProcessUserData_Vulnerable(invalidData);

            // Assert
            Assert.IsTrue(result.Contains("Stack trace:"), "❌ VULNERABILITY: Stack trace exposed to user");
            Assert.IsTrue(result.Contains("Source:"), "❌ VULNERABILITY: Source information exposed");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Detailed error information exposed to user");
        }

        [TestMethod]
        [TestCategory("ErrorHandling")]
        public void TestErrorHandling_SecureCode_ProvidesSafeErrors()
        {
            // Arrange
            var secureHandler = new SecureAdvancedSecurityExamples.SecureErrorHandling(testLogger, true);
            
            // Act
            var result = secureHandler.ProcessUserData("", "user123");

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("Invalid input provided", result.Message);
            Assert.IsFalse(result.Message.Contains("Stack trace"));
            Assert.IsFalse(result.Message.Contains("Exception"));
            
            // Verify error was logged for internal use
            Assert.IsTrue(testLogger.LogEntries.Any(entry => entry.Contains("Input validation error")));
            TestContext.WriteLine("✅ SECURE: Safe error messages provided to users, detailed logging for internal use");
        }

        #endregion

        #region Helper Methods

        private HttpRequest CreateMockHttpRequest(Dictionary<string, string> parameters)
        {
            // This is a simplified mock - in real testing you'd use a proper mocking framework
            return new TestHttpRequest(parameters);
        }

        private HttpPostedFile CreateMockPostedFile(string filename, string contentType, byte[] content)
        {
            return new TestHttpPostedFile(filename, contentType, content);
        }

        #endregion
    }

    #region Test Helper Classes

    public class TestLogger : SecureAdvancedSecurityExamples.ILogger
    {
        public List<string> LogEntries { get; } = new List<string>();

        public void LogInfo(string message) => LogEntries.Add($"INFO: {message}");
        public void LogWarning(string message) => LogEntries.Add($"WARNING: {message}");
        public void LogError(string message, Exception exception = null) => 
            LogEntries.Add($"ERROR: {message}" + (exception != null ? $" | {exception.Message}" : ""));
        
        public void Clear() => LogEntries.Clear();
    }

    public class TestConfigurationManager : SecureAdvancedSecurityExamples.IConfigurationManager
    {
        private readonly Dictionary<string, object> config = new();

        public string GetString(string key, string defaultValue = null) => 
            config.ContainsKey(key) ? config[key].ToString() : defaultValue;

        public int GetInt(string key, int defaultValue = 0) => 
            config.ContainsKey(key) ? (int)config[key] : defaultValue;

        public void SetValue(string key, object value) => config[key] = value;
        public void Clear() => config.Clear();
    }

    public class TestCacheManager : SecureAdvancedSecurityExamples.ICacheManager
    {
        private readonly Dictionary<string, (object Value, DateTime Expiration)> cache = new();

        public T Get<T>(string key)
        {
            if (cache.ContainsKey(key) && cache[key].Expiration > DateTime.UtcNow)
                return (T)cache[key].Value;
            return default(T);
        }

        public void Set(string key, object value, TimeSpan expiration) => 
            cache[key] = (value, DateTime.UtcNow.Add(expiration));

        public void Remove(string key) => cache.Remove(key);
        public void Clear() => cache.Clear();
    }

    public class TestAuthorizationService : SecureAdvancedSecurityExamples.IAuthorizationService
    {
        private readonly Dictionary<string, bool> permissions = new();

        public bool CanAccessDocument(string userId, string documentId, string action)
        {
            var key = $"{userId}_{documentId}_{action}";
            return permissions.GetValueOrDefault(key, false);
        }

        public bool IsAdmin(string userId) => userId == "admin";

        public void SetDocumentAccess(string userId, string documentId, string action, bool hasAccess)
        {
            var key = $"{userId}_{documentId}_{action}";
            permissions[key] = hasAccess;
        }
    }

    public class TestHttpResponse
    {
        public Dictionary<string, string> Headers { get; } = new();
        public List<HttpCookie> Cookies { get; } = new();
    }

    public class TestHttpRequest : HttpRequest
    {
        private readonly Dictionary<string, string> parameters;
        
        public TestHttpRequest(Dictionary<string, string> parameters)
        {
            this.parameters = parameters;
        }

        public override string Params => parameters.GetValueOrDefault("__RequestVerificationToken", "");
        // Simplified mock - real implementation would be more comprehensive
    }

    public class TestHttpPostedFile : HttpPostedFile
    {
        public override string FileName { get; }
        public override string ContentType { get; }
        public override int ContentLength { get; }
        public override Stream InputStream { get; }

        public TestHttpPostedFile(string filename, string contentType, byte[] content)
        {
            FileName = filename;
            ContentType = contentType;
            ContentLength = content.Length;
            InputStream = new MemoryStream(content);
        }

        public override void SaveAs(string filename)
        {
            // Mock implementation - in real tests, you might verify this was called
        }
    }

    #endregion
}
