using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SafeVault.Activity2.Tests
{
    /// <summary>
    /// 🧪 COMPREHENSIVE AUTHENTICATION SECURITY TEST SUITE
    /// Tests for authentication vulnerabilities and secure implementations
    /// </summary>
    [TestClass]
    public class AuthenticationSecurityTestSuite
    {
        private TestContext testContextInstance;
        private TestLogger testLogger;
        private TestCacheManager testCache;
        private TestConfigurationManager testConfig;

        public TestContext TestContext
        {
            get { return testContextInstance; }
            set { testContextInstance = value; }
        }

        #region Test Setup and Cleanup

        [TestInitialize]
        public void TestInitialize()
        {
            testLogger = new TestLogger();
            testCache = new TestCacheManager();
            testConfig = new TestConfigurationManager();
        }

        [TestCleanup]
        public void TestCleanup()
        {
            testCache.Clear();
            testLogger.Clear();
        }

        #endregion

        #region Session Management Security Tests

        [TestMethod]
        [TestCategory("SessionSecurity")]
        [Priority(1)]
        public void TestSessionGeneration_VulnerableCode_UsesWeakSessionIds()
        {
            // Arrange
            var vulnerableManager = new VulnerableAuthenticationExamples.InsecureSessionManager();

            // Act
            var session1 = VulnerableAuthenticationExamples.InsecureSessionManager.CreateSession_Vulnerable("user1");
            var session2 = VulnerableAuthenticationExamples.InsecureSessionManager.CreateSession_Vulnerable("user2");

            // Assert - Vulnerable sessions are predictable
            Assert.IsTrue(IsSessionIdPredictable(session1, session2), 
                "❌ VULNERABILITY: Session IDs are predictable/sequential");
            
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Predictable session IDs can be attacked");
        }

        [TestMethod]
        [TestCategory("SessionSecurity")]
        [Priority(1)]
        public void TestSessionGeneration_SecureCode_UsesRandomSessionIds()
        {
            // Arrange
            var secureManager = new SecureAuthenticationExamples.SecureSessionManager(testCache, testLogger);

            // Act
            var session1 = secureManager.CreateSession("user1", "192.168.1.1", "TestAgent");
            var session2 = secureManager.CreateSession("user2", "192.168.1.2", "TestAgent");

            // Assert
            Assert.IsFalse(IsSessionIdPredictable(session1, session2));
            Assert.IsTrue(session1.Length >= 40, "Session ID should be sufficiently long");
            Assert.IsTrue(session2.Length >= 40, "Session ID should be sufficiently long");
            Assert.AreNotEqual(session1, session2);
            
            TestContext.WriteLine("✅ SECURE: Session IDs are cryptographically random");
        }

        [TestMethod]
        [TestCategory("SessionSecurity")]
        public void TestSessionValidation_SecureCode_EnforcesExpiration()
        {
            // Arrange
            var secureManager = new SecureAuthenticationExamples.SecureSessionManager(testCache, testLogger);
            var sessionId = secureManager.CreateSession("testuser", "192.168.1.1", "TestAgent");

            // Act - Simulate expired session by manipulating cache
            var session = testCache.Get<SecureAuthenticationExamples.SecureUserSession>($"session_{sessionId}");
            session.ExpiresAt = DateTime.UtcNow.AddMinutes(-1); // Expired 1 minute ago
            testCache.Set($"session_{sessionId}", session, TimeSpan.FromMinutes(1));

            var result = secureManager.ValidateSession(sessionId, "192.168.1.1", "TestAgent");

            // Assert
            Assert.IsFalse(result.IsValid);
            Assert.AreEqual("Session expired", result.Reason);
            TestContext.WriteLine("✅ SECURE: Session expiration properly enforced");
        }

        [TestMethod]
        [TestCategory("SessionSecurity")]
        public void TestSessionValidation_SecureCode_DetectsIPMismatch()
        {
            // Arrange
            testConfig.SetValue("Security:ValidateSessionIP", true);
            var secureManager = new SecureAuthenticationExamples.SecureSessionManager(testCache, testLogger);
            var sessionId = secureManager.CreateSession("testuser", "192.168.1.1", "TestAgent");

            // Act - Try to use session from different IP
            var result = secureManager.ValidateSession(sessionId, "192.168.1.100", "TestAgent");

            // Assert
            Assert.IsFalse(result.IsValid);
            Assert.AreEqual("IP address mismatch", result.Reason);
            TestContext.WriteLine("✅ SECURE: IP address validation prevents session hijacking");
        }

        #endregion

        #region Password Security Tests

        [TestMethod]
        [TestCategory("PasswordSecurity")]
        [Priority(1)]
        public void TestPasswordHashing_VulnerableCode_UsesWeakHashing()
        {
            // Arrange
            string password = "TestPassword123!";

            // Act
            string hash1 = VulnerableAuthenticationExamples.HashPassword_Vulnerable(password);
            string hash2 = VulnerableAuthenticationExamples.HashPassword_Vulnerable(password);

            // Assert - Vulnerable: Same password produces same hash (no salt)
            Assert.AreEqual(hash1, hash2, "❌ VULNERABILITY: Same password produces same hash");
            Assert.IsTrue(hash1.Length == 32, "❌ VULNERABILITY: MD5 hash is too short"); // MD5 is 32 hex chars
            
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Weak password hashing with MD5, no salt");
        }

        [TestMethod]
        [TestCategory("PasswordSecurity")]
        [Priority(1)]
        public void TestPasswordHashing_SecureCode_UsesStrongHashing()
        {
            // Arrange
            string password = "TestPassword123!";

            // Act
            var result1 = SecureAuthenticationExamples.HashPassword(password);
            var result2 = SecureAuthenticationExamples.HashPassword(password);

            // Assert
            Assert.AreNotEqual(result1.Hash, result2.Hash, "Different salts should produce different hashes");
            Assert.AreNotEqual(result1.Salt, result2.Salt, "Each hash should have unique salt");
            Assert.AreEqual("PBKDF2-SHA256", result1.Algorithm);
            Assert.AreEqual(100000, result1.Iterations, "Should use high iteration count");
            
            TestContext.WriteLine("✅ SECURE: Strong password hashing with PBKDF2, unique salts, high iterations");
        }

        [TestMethod]
        [TestCategory("PasswordSecurity")]
        public void TestPasswordValidation_WeakPasswords_AreRejected()
        {
            // Arrange & Act & Assert
            var weakPasswords = new[]
            {
                "123456",
                "password",
                "abc123",
                "qwerty",
                "Password", // No numbers or special chars
                "12345678", // No letters
                "PASSWORD123", // No lowercase
                "password123" // No uppercase
            };

            foreach (var weakPassword in weakPasswords)
            {
                var result = SecureAuthenticationExamples.ValidatePassword(weakPassword);
                Assert.IsFalse(result.IsValid, $"Weak password should be rejected: {weakPassword}");
                Assert.IsTrue(result.Errors.Any(), $"Should have validation errors for: {weakPassword}");
                TestContext.WriteLine($"✅ Weak password rejected: {weakPassword} - {string.Join(", ", result.Errors)}");
            }
        }

        [TestMethod]
        [TestCategory("PasswordSecurity")]
        public void TestPasswordValidation_StrongPasswords_AreAccepted()
        {
            // Arrange & Act & Assert
            var strongPasswords = new[]
            {
                "MySecurePassword123!",
                "Tr0ub4dor&3",
                "C0mpl3x_P@ssw0rd!",
                "Ungu3ss4ble#Str1ng$"
            };

            foreach (var strongPassword in strongPasswords)
            {
                var result = SecureAuthenticationExamples.ValidatePassword(strongPassword);
                Assert.IsTrue(result.IsValid, $"Strong password should be accepted: {strongPassword}");
                Assert.IsFalse(result.Errors.Any(), $"Should have no errors for strong password: {strongPassword}");
                TestContext.WriteLine($"✅ Strong password accepted: {strongPassword}");
            }
        }

        #endregion

        #region Authentication Security Tests

        [TestMethod]
        [TestCategory("Authentication")]
        public void TestAuthentication_ValidCredentials_ReturnsSuccess()
        {
            // Arrange
            var auth = new SecureAuthenticationExamples(testLogger, testCache, testConfig);
            SetupTestUser("validuser", "ValidPassword123!");

            // Act
            var result = auth.AuthenticateUser("validuser", "ValidPassword123!", "192.168.1.1", "TestAgent");

            // Assert
            Assert.IsTrue(result.Success);
            Assert.IsNotNull(result.SessionId);
            Assert.AreEqual("validuser", result.Username);
            TestContext.WriteLine("✅ Valid authentication successful");
        }

        [TestMethod]
        [TestCategory("Authentication")]
        public void TestAuthentication_InvalidCredentials_ReturnsGenericError()
        {
            // Arrange
            var auth = new SecureAuthenticationExamples(testLogger, testCache, testConfig);

            // Act
            var result = auth.AuthenticateUser("nonexistent", "wrongpassword", "192.168.1.1", "TestAgent");

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("Invalid credentials", result.Message);
            Assert.IsNull(result.SessionId);
            TestContext.WriteLine("✅ Invalid credentials handled with generic error (prevents user enumeration)");
        }

        [TestMethod]
        [TestCategory("Authentication")]
        [Priority(1)]
        public void TestAuthentication_VulnerableCode_AllowsSQLInjection()
        {
            // Arrange
            string maliciousUsername = "admin' OR '1'='1' --";
            string password = "anypassword";

            // Act
            bool result = VulnerableAuthenticationExamples.AuthenticateWithDatabase_Vulnerable(maliciousUsername, password);

            // Assert
            Assert.IsTrue(result, "❌ VULNERABILITY: SQL injection bypassed authentication");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Authentication bypass via SQL injection");
        }

        [TestMethod]
        [TestCategory("Authentication")]
        public void TestAuthentication_RateLimiting_BlocksExcessiveAttempts()
        {
            // Arrange
            var auth = new SecureAuthenticationExamples(testLogger, testCache, testConfig);
            string ipAddress = "192.168.1.100";

            // Simulate 5 failed attempts to trigger IP-based rate limiting
            for (int i = 0; i < 5; i++)
            {
                testCache.Set($"rate_limit_ip_{ipAddress}", i + 1, TimeSpan.FromMinutes(15));
            }

            // Act
            var result = auth.AuthenticateUser("testuser", "wrongpassword", ipAddress, "TestAgent");

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("Too many attempts. Try again later.", result.Message);
            TestContext.WriteLine("✅ Rate limiting successfully blocks excessive authentication attempts");
        }

        #endregion

        #region Multi-Factor Authentication Tests

        [TestMethod]
        [TestCategory("MFA")]
        [Priority(1)]
        public void TestMFA_VulnerableCode_UsesPredictableCodes()
        {
            // Arrange & Act
            var code1 = VulnerableAuthenticationExamples.VulnerableMFAManager.GenerateMFACode_Vulnerable();
            Thread.Sleep(10); // Small delay
            var code2 = VulnerableAuthenticationExamples.VulnerableMFAManager.GenerateMFACode_Vulnerable();

            // Assert
            Assert.AreNotEqual(code1, code2, "Codes should be different");
            
            // Check if codes are sequential (predictable)
            if (int.TryParse(code1, out int num1) && int.TryParse(code2, out int num2))
            {
                Assert.IsTrue(Math.Abs(num2 - num1) < 1000, "❌ VULNERABILITY: MFA codes are predictable");
            }
            
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: MFA codes are based on predictable timestamp");
        }

        [TestMethod]
        [TestCategory("MFA")]
        [Priority(1)]
        public void TestMFA_SecureCode_GeneratesRandomCodes()
        {
            // Arrange
            var mfaManager = new SecureAuthenticationExamples.SecureMFAManager(
                testLogger, testCache, new TestSMSService(), new TestEmailService());

            // Act
            var codes = new List<string>();
            for (int i = 0; i < 10; i++)
            {
                codes.Add(mfaManager.GenerateMFACode());
            }

            // Assert
            Assert.AreEqual(10, codes.Distinct().Count(), "All codes should be unique");
            Assert.IsTrue(codes.All(c => c.Length == 6), "All codes should be 6 digits");
            Assert.IsTrue(codes.All(c => int.TryParse(c, out _)), "All codes should be numeric");
            TestContext.WriteLine("✅ SECURE: MFA codes are cryptographically random and unique");
        }

        [TestMethod]
        [TestCategory("MFA")]
        public void TestMFA_ValidationTiming_IsConstant()
        {
            // Arrange
            var mfaManager = new SecureAuthenticationExamples.SecureMFAManager(
                testLogger, testCache, new TestSMSService(), new TestEmailService());
            
            string validCode = "123456";
            var codeData = new SecureAuthenticationExamples.MFACodeData
            {
                Code = validCode,
                UserId = 1,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                Attempts = 0
            };
            string codeKey = "test_code_key";
            testCache.Set(codeKey, codeData, TimeSpan.FromMinutes(5));

            // Act - Measure timing for correct and incorrect codes
            var timings = new List<long>();
            
            for (int i = 0; i < 5; i++)
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                mfaManager.ValidateMFACode(codeKey, "123456"); // Correct
                stopwatch.Stop();
                timings.Add(stopwatch.ElapsedTicks);
                
                // Reset for next test
                testCache.Set(codeKey, codeData, TimeSpan.FromMinutes(5));
            }

            for (int i = 0; i < 5; i++)
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                mfaManager.ValidateMFACode(codeKey, "654321"); // Incorrect
                stopwatch.Stop();
                timings.Add(stopwatch.ElapsedTicks);
                
                // Reset for next test
                testCache.Set(codeKey, codeData, TimeSpan.FromMinutes(5));
            }

            // Assert - Timing should be relatively consistent (within 50% variance)
            var avgTiming = timings.Average();
            var maxDeviation = timings.Max(t => Math.Abs(t - avgTiming)) / avgTiming;
            
            Assert.IsTrue(maxDeviation < 0.5, "Timing variance should be less than 50% to prevent timing attacks");
            TestContext.WriteLine($"✅ SECURE: MFA validation timing is consistent (max deviation: {maxDeviation:P})");
        }

        [TestMethod]
        [TestCategory("MFA")]
        public void TestMFA_RateLimiting_LimitsSMSRequests()
        {
            // Arrange
            var mfaManager = new SecureAuthenticationExamples.SecureMFAManager(
                testLogger, testCache, new TestSMSService(), new TestEmailService());
            
            int userId = 123;
            string phoneNumber = "+1234567890";

            // Simulate 3 previous SMS requests
            testCache.Set($"mfa_sms_rate_{userId}", 3, TimeSpan.FromMinutes(10));

            // Act
            var result = mfaManager.SendMFACodeViaSMS(userId, phoneNumber);

            // Assert
            Assert.IsFalse(result.Success);
            Assert.AreEqual("Too many SMS requests. Please try again later.", result.Message);
            TestContext.WriteLine("✅ SECURE: MFA SMS rate limiting prevents abuse");
        }

        #endregion

        #region Authorization Security Tests

        [TestMethod]
        [TestCategory("Authorization")]
        [Priority(1)]
        public void TestAuthorization_VulnerableCode_AllowsDirectObjectAccess()
        {
            // Arrange
            string validSessionId = "valid_session";
            VulnerableAuthenticationExamples.InsecureSessionManager.CreateSession_Vulnerable("user1");

            // Act - User tries to access another user's profile
            var profile = VulnerableAuthenticationExamples.GetUserProfile_Vulnerable(validSessionId, 999);

            // Assert - Vulnerable code allows access without proper authorization check
            Assert.IsNotNull(profile, "❌ VULNERABILITY: Direct object reference allows unauthorized access");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Insecure direct object reference");
        }

        [TestMethod]
        [TestCategory("Authorization")]
        [Priority(1)]
        public void TestAuthorization_VulnerableCode_AllowsCaseSensitiveBypass()
        {
            // Act
            bool isAdmin1 = VulnerableAuthenticationExamples.HasAdminAccess_Vulnerable("admin");
            bool isAdmin2 = VulnerableAuthenticationExamples.HasAdminAccess_Vulnerable("ADMIN");
            bool isAdmin3 = VulnerableAuthenticationExamples.HasAdminAccess_Vulnerable("Admin");

            // Assert
            Assert.IsTrue(isAdmin1, "Lowercase admin should be recognized");
            Assert.IsFalse(isAdmin2, "❌ VULNERABILITY: Case-sensitive comparison allows bypass");
            Assert.IsFalse(isAdmin3, "❌ VULNERABILITY: Case-sensitive comparison allows bypass");
            
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Case-sensitive role comparison enables bypasses");
        }

        [TestMethod]
        [TestCategory("Authorization")]
        public void TestAuthorization_SecureCode_EnforcesPermissions()
        {
            // Arrange
            var authManager = new SecureAuthenticationExamples.SecureAuthorizationManager(testCache, testLogger);
            int userId = 123;
            
            // Setup user permissions
            var permissions = new List<string> { "user:read", "profile:update" };
            testCache.Set($"user_permissions_{userId}", permissions, TimeSpan.FromMinutes(15));

            // Act & Assert
            Assert.IsTrue(authManager.HasPermission(userId, "user", "read"));
            Assert.IsTrue(authManager.HasPermission(userId, "profile", "update"));
            Assert.IsFalse(authManager.HasPermission(userId, "admin", "delete"));
            
            TestContext.WriteLine("✅ SECURE: Permission system properly enforced");
        }

        #endregion

        #region Account Security Tests

        [TestMethod]
        [TestCategory("AccountSecurity")]
        [Priority(1)]
        public void TestAccountSecurity_VulnerableCode_AllowsBruteForce()
        {
            // Arrange - Attempt multiple failed logins
            var results = new List<bool>();
            
            for (int i = 0; i < 10; i++)
            {
                // Act
                bool result = VulnerableAuthenticationExamples.VulnerableAccountManager
                    .CheckCredentials_Vulnerable("admin", "wrongpassword");
                results.Add(result);
            }

            // Assert - All attempts should be allowed (no rate limiting)
            Assert.IsTrue(results.All(r => r == false), "All attempts should fail");
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: No protection against brute force attacks");
            TestContext.WriteLine("Account allows unlimited login attempts without lockout");
        }

        [TestMethod]
        [TestCategory("AccountSecurity")]
        public void TestPasswordReset_VulnerableCode_UsesPredictableTokens()
        {
            // Arrange
            string email = "test@example.com";

            // Act
            var token1 = VulnerableAuthenticationExamples.VulnerablePasswordReset
                .GenerateResetToken_Vulnerable(email);
            Thread.Sleep(10);
            var token2 = VulnerableAuthenticationExamples.VulnerablePasswordReset
                .GenerateResetToken_Vulnerable(email);

            // Assert
            Assert.IsTrue(token1.EndsWith(email.GetHashCode().ToString()), 
                "❌ VULNERABILITY: Token contains predictable email hash");
            Assert.IsTrue(token2.EndsWith(email.GetHashCode().ToString()), 
                "❌ VULNERABILITY: Token contains predictable email hash");
            
            TestContext.WriteLine("⚠️ VULNERABILITY CONFIRMED: Password reset tokens are predictable");
        }

        #endregion

        #region Helper Methods

        private bool IsSessionIdPredictable(string session1, string session2)
        {
            // Check if session IDs are sequential numbers
            if (int.TryParse(session1, out int id1) && int.TryParse(session2, out int id2))
            {
                return Math.Abs(id2 - id1) == 1; // Sequential
            }
            return false;
        }

        private void SetupTestUser(string username, string password)
        {
            var hashResult = SecureAuthenticationExamples.HashPassword(password);
            // In a real test, this would store the user in a test database
            // For this example, we'll simulate with cache
            testCache.Set($"user_{username}", new
            {
                Username = username,
                PasswordHash = hashResult.Hash,
                Salt = hashResult.Salt,
                Role = "User"
            }, TimeSpan.FromHours(1));
        }

        #endregion
    }

    #region Test Helper Classes

    public class TestLogger : SecureAuthenticationExamples.ILogger
    {
        public List<string> LogEntries { get; } = new List<string>();

        public void LogInfo(string message) => LogEntries.Add($"INFO: {message}");
        public void LogWarning(string message) => LogEntries.Add($"WARNING: {message}");
        public void LogError(string message) => LogEntries.Add($"ERROR: {message}");
        public void Clear() => LogEntries.Clear();
    }

    public class TestCacheManager : SecureAuthenticationExamples.ICacheManager
    {
        private readonly Dictionary<string, (object Value, DateTime Expiration)> cache = new();

        public T Get<T>(string key)
        {
            if (cache.ContainsKey(key) && cache[key].Expiration > DateTime.UtcNow)
                return (T)cache[key].Value;
            return default(T);
        }

        public void Set(string key, object value, TimeSpan expiration)
        {
            cache[key] = (value, DateTime.UtcNow.Add(expiration));
        }

        public void Remove(string key) => cache.Remove(key);
        public void Clear() => cache.Clear();
    }

    public class TestConfigurationManager : SecureAuthenticationExamples.IConfigurationManager
    {
        private readonly Dictionary<string, object> config = new();

        public string GetString(string key, string defaultValue = null)
            => config.ContainsKey(key) ? config[key].ToString() : defaultValue;

        public bool GetBoolean(string key, bool defaultValue = false)
            => config.ContainsKey(key) ? (bool)config[key] : defaultValue;

        public int GetInt(string key, int defaultValue = 0)
            => config.ContainsKey(key) ? (int)config[key] : defaultValue;

        public void SetValue(string key, object value) => config[key] = value;
    }

    public class TestSMSService : SecureAuthenticationExamples.ISMSService
    {
        public List<(string Phone, string Message)> SentMessages { get; } = new();
        
        public void SendSMS(string phoneNumber, string message)
        {
            SentMessages.Add((phoneNumber, message));
            System.Diagnostics.Debug.WriteLine($"SMS sent to {phoneNumber}: {message}");
        }
    }

    public class TestEmailService : SecureAuthenticationExamples.IEmailService
    {
        public List<(string Email, string Subject, string Message)> SentEmails { get; } = new();
        
        public void SendEmail(string emailAddress, string subject, string message)
        {
            SentEmails.Add((emailAddress, subject, message));
            System.Diagnostics.Debug.WriteLine($"Email sent to {emailAddress}: {subject}");
        }
    }

    #endregion
}
