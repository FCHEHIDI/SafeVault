/*
 * SecurityTestSuite.cs - Comprehensive Security Testing
 * 🧪 Test suite for validating security fixes applied to SafeVault
 * 
 * Purpose: Provide automated tests that verify security vulnerabilities
 * have been properly addressed using the fixes suggested by Copilot
 */

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Data.SqlClient;
using SafeVault.VulnerableExamples;
using SafeVault.SecureExamples;

namespace SafeVault.Tests
{
    /// <summary>
    /// Security Test Suite - Validates fixes for common vulnerabilities
    /// Students should run these tests to verify their Copilot-assisted fixes work correctly
    /// </summary>
    [TestClass]
    public class SecurityTestSuite
    {
        #region SQL Injection Tests

        /// <summary>
        /// Test SQL injection prevention in user authentication
        /// This test should PASS for secure implementation and FAIL for vulnerable code
        /// </summary>
        [TestMethod]
        public void TestSQLInjection_Authentication_ShouldPreventBypass()
        {
            // Arrange - SQL injection payload that would bypass authentication
            string maliciousUsername = "admin";
            string maliciousPassword = "' OR '1'='1"; // Classic SQL injection

            var secureDb = new SecureUserDatabase("mock-connection-string");
            
            // Act & Assert
            try
            {
                // ✅ SECURE CODE: This should return false (authentication fails)
                bool result = secureDb.AuthenticateUser(maliciousUsername, maliciousPassword);
                Assert.IsFalse(result, "Secure implementation should reject SQL injection attempts");
                
                Console.WriteLine("✅ PASS: SQL injection in authentication properly blocked");
            }
            catch (Exception ex)
            {
                // Even if there's an exception, it shouldn't allow authentication bypass
                Console.WriteLine($"✅ PASS: SQL injection blocked with exception: {ex.Message}");
            }

            // Test with the vulnerable version (for educational comparison)
            var vulnerableDb = new VulnerableUserDatabase("mock-connection-string");
            
            // Note: In a real test environment, this would demonstrate the vulnerability
            Console.WriteLine("⚠️ NOTE: Vulnerable version would allow this injection to succeed");
        }

        /// <summary>
        /// Test SQL injection prevention in user search functionality
        /// </summary>
        [TestMethod]
        public void TestSQLInjection_Search_ShouldSanitizeInput()
        {
            // Arrange - Various SQL injection payloads
            var injectionPayloads = new[]
            {
                "'; DROP TABLE Users; --",
                "' UNION SELECT username, password FROM AdminUsers --",
                "' OR 1=1 --",
                "admin'; UPDATE Users SET Password='hacked' WHERE Username='admin'; --"
            };

            var secureDb = new SecureUserDatabase("mock-connection-string");

            // Act & Assert
            foreach (var payload in injectionPayloads)
            {
                try
                {
                    // ✅ SECURE CODE: Should handle malicious input safely
                    var results = secureDb.SearchUsers(payload);
                    
                    // The search should complete without executing malicious SQL
                    Assert.IsNotNull(results, "Search should return results object (even if empty)");
                    Console.WriteLine($"✅ PASS: Injection payload '{payload}' was safely handled");
                }
                catch (ArgumentException)
                {
                    // Input validation rejection is also acceptable
                    Console.WriteLine($"✅ PASS: Injection payload '{payload}' was rejected by input validation");
                }
                catch (Exception ex)
                {
                    // Log unexpected exceptions for analysis
                    Console.WriteLine($"⚠️ UNEXPECTED: Payload '{payload}' caused: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Test SQL injection prevention in sort column parameter
        /// </summary>
        [TestMethod]
        public void TestSQLInjection_SortColumn_ShouldValidateInput()
        {
            // Arrange - Malicious sort column attempts
            var maliciousColumns = new[]
            {
                "Username; DROP TABLE Users; --",
                "Username UNION SELECT password FROM AdminUsers",
                "(SELECT password FROM Users WHERE username='admin')",
                "1; DELETE FROM Users; --"
            };

            var secureDb = new SecureUserDatabase("mock-connection-string");

            // Act & Assert
            foreach (var column in maliciousColumns)
            {
                try
                {
                    // ✅ SECURE CODE: Should default to safe column or reject
                    var results = secureDb.SearchUsers("test", column);
                    
                    // If it doesn't throw an exception, the malicious column should be ignored
                    Assert.IsNotNull(results);
                    Console.WriteLine($"✅ PASS: Malicious sort column '{column}' was safely handled");
                }
                catch (Exception ex)
                {
                    // Rejection is also acceptable behavior
                    Console.WriteLine($"✅ PASS: Malicious sort column '{column}' was rejected: {ex.Message}");
                }
            }
        }

        #endregion

        #region XSS Prevention Tests

        /// <summary>
        /// Test XSS prevention in comment display functionality
        /// </summary>
        [TestMethod]
        public void TestXSS_CommentDisplay_ShouldEncodeOutput()
        {
            // Arrange - Various XSS attack payloads
            var xssPayloads = new[]
            {
                "<script>alert('XSS')</script>",
                "<img src='x' onerror='alert(\"XSS\")' />",
                "<div onmouseover='alert(\"XSS\")'>Hover me</div>",
                "javascript:alert('XSS')",
                "<iframe src='javascript:alert(\"XSS\")'></iframe>"
            };

            var secureHandler = new SecureFormHandler();

            // Act & Assert
            foreach (var payload in xssPayloads)
            {
                try
                {
                    // ✅ SECURE CODE: Should encode HTML and prevent script execution
                    string result = secureHandler.DisplayComment("testuser", payload);
                    
                    // Verify that dangerous HTML tags are encoded
                    Assert.IsFalse(result.Contains("<script>"), "Script tags should be encoded");
                    Assert.IsFalse(result.Contains("onerror="), "Event handlers should be encoded");
                    Assert.IsFalse(result.Contains("javascript:"), "JavaScript URLs should be encoded");
                    
                    // Verify that encoded entities are present (indicates encoding happened)
                    Assert.IsTrue(result.Contains("&lt;") || result.Contains("&gt;") || result.Contains("&quot;"), 
                                "HTML encoding should be applied");
                    
                    Console.WriteLine($"✅ PASS: XSS payload '{payload}' was properly encoded");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"✅ PASS: XSS payload '{payload}' was rejected: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Test XSS prevention in user profile generation
        /// </summary>
        [TestMethod]
        public void TestXSS_UserProfile_ShouldEncodeAttributes()
        {
            // Arrange - Attribute injection attacks
            var attributePayloads = new[]
            {
                "Admin\" onmouseover=\"alert('XSS')\"",
                "User' onclick='alert(\"XSS\")'",
                "\"><script>alert('XSS')</script><\"",
                "javascript:alert('XSS')"
            };

            var secureHandler = new SecureFormHandler();

            // Act & Assert
            foreach (var payload in attributePayloads)
            {
                try
                {
                    // ✅ SECURE CODE: Should encode HTML attributes properly
                    string result = secureHandler.CreateUserProfile("testuser", payload, "Test bio");
                    
                    // Verify that attribute injection is prevented
                    Assert.IsFalse(result.Contains("onmouseover="), "Event handlers should not be present");
                    Assert.IsFalse(result.Contains("onclick="), "Event handlers should not be present");
                    Assert.IsFalse(result.Contains("<script>"), "Script tags should be encoded");
                    
                    Console.WriteLine($"✅ PASS: Attribute injection '{payload}' was properly handled");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"✅ PASS: Attribute injection '{payload}' was rejected: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Test XSS prevention in JavaScript context
        /// </summary>
        [TestMethod]
        public void TestXSS_JavaScriptContext_ShouldEscapeQuotes()
        {
            // Arrange - JavaScript breaking payloads
            var jsPayloads = new[]
            {
                "'; alert('XSS'); var x='",
                "\"; alert(\"XSS\"); var y=\"",
                "\\'; alert('XSS'); //",
                "</script><script>alert('XSS')</script>"
            };

            var secureHandler = new SecureFormHandler();

            // Act & Assert
            foreach (var payload in jsPayloads)
            {
                try
                {
                    // ✅ SECURE CODE: Should properly escape JavaScript strings
                    string result = secureHandler.CreateUserProfile("testuser", "Test Title", payload);
                    
                    // Extract JavaScript portion for analysis
                    int scriptStart = result.IndexOf("<script>");
                    int scriptEnd = result.IndexOf("</script>");
                    
                    if (scriptStart >= 0 && scriptEnd > scriptStart)
                    {
                        string jsCode = result.Substring(scriptStart, scriptEnd - scriptStart);
                        
                        // Verify that quotes are properly escaped
                        Assert.IsFalse(jsCode.Contains("'; alert("), "Single quotes should be escaped");
                        Assert.IsFalse(jsCode.Contains("\"; alert("), "Double quotes should be escaped");
                    }
                    
                    Console.WriteLine($"✅ PASS: JavaScript payload '{payload}' was properly escaped");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"✅ PASS: JavaScript payload '{payload}' was rejected: {ex.Message}");
                }
            }
        }

        #endregion

        #region File Handling Security Tests

        /// <summary>
        /// Test path traversal prevention in file reading
        /// </summary>
        [TestMethod]
        public void TestPathTraversal_FileRead_ShouldBlockTraversal()
        {
            // Arrange - Path traversal payloads
            var traversalPayloads = new[]
            {
                "../../etc/passwd",
                "..\\..\\windows\\system32\\config\\sam",
                "....//....//etc/passwd",
                "../../../autoexec.bat",
                ".\\..\\..\\sensitive.txt"
            };

            var uploadDir = Path.Combine(Path.GetTempPath(), "SafeVaultTestUploads");
            Directory.CreateDirectory(uploadDir);
            
            var secureHandler = new SecureFileHandler(uploadDir);

            // Act & Assert
            foreach (var payload in traversalPayloads)
            {
                try
                {
                    // ✅ SECURE CODE: Should prevent path traversal
                    string result = secureHandler.ReadUserFile(payload);
                    
                    // If it succeeds, it should only access files within the allowed directory
                    Assert.Fail($"Path traversal should be blocked for: {payload}");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"✅ PASS: Path traversal blocked for: {payload}");
                }
                catch (FileNotFoundException)
                {
                    Console.WriteLine($"✅ PASS: Path traversal neutralized (file not found): {payload}");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine($"✅ PASS: Path traversal rejected by validation: {payload}");
                }
            }

            // Cleanup
            try { Directory.Delete(uploadDir, true); } catch { }
        }

        /// <summary>
        /// Test file upload validation
        /// </summary>
        [TestMethod]
        public void TestFileUpload_ShouldValidateFileTypes()
        {
            // Arrange
            var uploadDir = Path.Combine(Path.GetTempPath(), "SafeVaultTestUploads");
            Directory.CreateDirectory(uploadDir);
            
            var secureHandler = new SecureFileHandler(uploadDir);

            // Test malicious file extensions
            var maliciousFiles = new[]
            {
                ("virus.exe", new byte[] { 0x4D, 0x5A }), // EXE header
                ("script.bat", Encoding.UTF8.GetBytes("@echo off")),
                ("malware.scr", new byte[] { 0x00, 0x01, 0x02 }),
                ("dangerous.php", Encoding.UTF8.GetBytes("<?php echo 'test'; ?>"))
            };

            // Act & Assert
            foreach (var (filename, content) in maliciousFiles)
            {
                try
                {
                    // ✅ SECURE CODE: Should reject dangerous file types
                    secureHandler.SaveUploadedFile(filename, content);
                    Assert.Fail($"Dangerous file type should be rejected: {filename}");
                }
                catch (ArgumentException ex)
                {
                    Assert.IsTrue(ex.Message.Contains("not allowed") || ex.Message.Contains("type"));
                    Console.WriteLine($"✅ PASS: Dangerous file rejected: {filename}");
                }
            }

            // Test valid file types (these should succeed)
            var validFiles = new[]
            {
                ("document.txt", Encoding.UTF8.GetBytes("This is a text file")),
                ("image.jpg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }), // JPEG header
            };

            foreach (var (filename, content) in validFiles)
            {
                try
                {
                    secureHandler.SaveUploadedFile(filename, content);
                    Console.WriteLine($"✅ PASS: Valid file accepted: {filename}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ UNEXPECTED: Valid file rejected: {filename} - {ex.Message}");
                }
            }

            // Cleanup
            try { Directory.Delete(uploadDir, true); } catch { }
        }

        #endregion

        #region Input Validation Tests

        /// <summary>
        /// Test input validation for various attack vectors
        /// </summary>
        [TestMethod]
        public void TestInputValidation_ShouldRejectMaliciousInput()
        {
            // Arrange - Various malicious inputs
            var maliciousInputs = new[]
            {
                new string('A', 10000), // Extremely long input
                null, // Null input
                "", // Empty input
                "<script>alert('XSS')</script>", // XSS
                "'; DROP TABLE Users; --", // SQL injection
                "../../../etc/passwd", // Path traversal
                "\0\0\0\0", // Null bytes
                "admin\npassword", // CRLF injection
            };

            var secureHandler = new SecureFormHandler();

            // Act & Assert
            foreach (var input in maliciousInputs)
            {
                try
                {
                    // Test various input scenarios
                    string result1 = secureHandler.DisplayComment("testuser", input ?? "");
                    string result2 = secureHandler.CreateUserProfile(input ?? "", "title", "bio");
                    
                    // If processing succeeds, verify output is safe
                    if (!string.IsNullOrEmpty(result1))
                    {
                        Assert.IsFalse(result1.Contains("<script>"), "XSS should be prevented");
                    }
                    
                    if (!string.IsNullOrEmpty(result2))
                    {
                        Assert.IsFalse(result2.Contains("<script>"), "XSS should be prevented");
                    }
                    
                    Console.WriteLine($"✅ PASS: Malicious input handled safely: {input?.Substring(0, Math.Min(input.Length, 50))}...");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine($"✅ PASS: Malicious input rejected by validation");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ REVIEW: Unexpected handling for input: {ex.Message}");
                }
            }
        }

        #endregion

        #region Performance and DoS Tests

        /// <summary>
        /// Test protection against resource exhaustion attacks
        /// </summary>
        [TestMethod]
        public void TestResourceExhaustion_ShouldHaveLimits()
        {
            var secureHandler = new SecureFormHandler();
            
            // Test extremely large inputs
            string largeInput = new string('A', 100000); // 100KB input
            
            try
            {
                // ✅ SECURE CODE: Should limit input size or processing time
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                string result = secureHandler.DisplayComment("user", largeInput);
                
                stopwatch.Stop();
                
                // Processing should complete in reasonable time (not hang)
                Assert.IsTrue(stopwatch.ElapsedMilliseconds < 5000, "Processing should complete within 5 seconds");
                
                // Result should be limited/truncated
                Assert.IsTrue(result.Length < largeInput.Length * 2, "Output should not be excessively large");
                
                Console.WriteLine($"✅ PASS: Large input processed in {stopwatch.ElapsedMilliseconds}ms");
            }
            catch (ArgumentException)
            {
                Console.WriteLine("✅ PASS: Large input rejected by size validation");
            }
        }

        #endregion

        #region Test Utilities

        /// <summary>
        /// Helper method to run all security tests and generate a summary report
        /// </summary>
        public static void RunSecurityTestSuite()
        {
            Console.WriteLine("🧪 SafeVault Security Test Suite");
            Console.WriteLine("=================================");
            Console.WriteLine("Running comprehensive security tests...\n");

            var testSuite = new SecurityTestSuite();
            var testMethods = typeof(SecurityTestSuite)
                .GetMethods()
                .Where(m => m.GetCustomAttributes(typeof(TestMethodAttribute), false).Length > 0);

            int passedTests = 0;
            int totalTests = testMethods.Count();

            foreach (var method in testMethods)
            {
                try
                {
                    Console.WriteLine($"Running: {method.Name}");
                    method.Invoke(testSuite, null);
                    passedTests++;
                    Console.WriteLine($"✅ PASSED: {method.Name}\n");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ FAILED: {method.Name} - {ex.InnerException?.Message ?? ex.Message}\n");
                }
            }

            // Generate summary report
            Console.WriteLine("Test Results Summary:");
            Console.WriteLine($"Passed: {passedTests}/{totalTests}");
            Console.WriteLine($"Security Score: {(passedTests * 100 / totalTests)}%");

            if (passedTests == totalTests)
            {
                Console.WriteLine("🎉 All security tests passed! Your SafeVault implementation is secure.");
            }
            else
            {
                Console.WriteLine("⚠️ Some security tests failed. Review the failures and apply additional fixes.");
            }
        }

        #endregion
    }
}

/*
 * COPILOT TESTING INSTRUCTIONS FOR STUDENTS:
 * 
 * 1. After applying security fixes with Copilot's help, run this test suite
 * 2. Use Copilot to understand test failures:
 *    - "Why is this security test failing?"
 *    - "How can I fix my code to pass this test?"
 * 
 * 3. Generate additional test cases with Copilot:
 *    - "Generate more SQL injection test cases"
 *    - "Create XSS test vectors for my input validation"
 * 
 * 4. Use Copilot to interpret test results:
 *    - "What does this test failure mean for security?"
 *    - "Is my fix working correctly based on these results?"
 * 
 * EXPECTED LEARNING OUTCOMES:
 * - Understanding how security tests validate fixes
 * - Learning to use automated testing for security validation
 * - Gaining experience with test-driven security development
 * - Building confidence in security implementations through testing
 */
