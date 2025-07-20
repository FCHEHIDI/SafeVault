using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;

/// <summary>
/// SafeVault Security Learning Platform
/// Educational cybersecurity platform demonstrating secure coding practices
/// Author: SafeVault Team
/// Purpose: Interactive learning through practical security implementations
/// </summary>

// Enable top-level async for interactive demos
await MainAsync();

static async Task MainAsync()
{
    Console.WriteLine("🔐 SafeVault Security Learning Platform");
    Console.WriteLine("======================================");
    Console.WriteLine("📚 Interactive Cybersecurity Education");
    Console.WriteLine("🛡️ Learn by Testing Real Security Implementations\n");

    Console.WriteLine("Choose an activity:");
    Console.WriteLine("1. Activity 1: Input Validation & SQL Security");
    Console.WriteLine("2. Activity 2: Authentication & Authorization");  
    Console.WriteLine("3. Activity 3: Advanced Security Features");
    Console.WriteLine("4. Activity 4: Debugging & Resolving Vulnerabilities");
    Console.WriteLine("5. Open Web Interface");
    Console.WriteLine("6. Run Interactive Security Demo");
    Console.WriteLine("7. Exit");

    Console.Write("\nChoice (1-7): ");
    var input = Console.ReadLine();

    switch (input)
    {
        case "1":
            ShowActivity1();
            break;
        case "2":
            ShowActivity2();
            break;
        case "3":
            ShowActivity3();
            break;
        case "4":
            ShowActivity4();
            break;
        case "5":
            OpenWebInterface();
            break;
        case "6":
            await RunInteractiveSecurityDemo();
            break;
        default:
            Console.WriteLine("Goodbye! Stay secure! 🛡️");
            return;
    }

    Console.WriteLine("\nPress Enter to exit...");
    Console.ReadLine();
}

static void ShowActivity1()
{
    Console.WriteLine("\n🛡️ Activity 1: Input Validation & SQL Protection");
    Console.WriteLine("================================================");
    Console.WriteLine("✓ XSS Prevention Techniques");
    Console.WriteLine("✓ SQL Injection Protection");  
    Console.WriteLine("✓ Input Sanitization Methods");
    Console.WriteLine("\n📁 Files: Activities/Activity1_SecureAudit/");
    Console.WriteLine("📖 Guide: Activities/Activity1_SecureAudit/COMPLETION_GUIDE.md");
    Console.WriteLine("🌐 Demo: Open the web interface to test vulnerabilities");
}

static void ShowActivity2()
{
    Console.WriteLine("\n🔑 Activity 2: Authentication & Authorization");
    Console.WriteLine("==============================================");
    Console.WriteLine("✓ Secure Password Hashing");
    Console.WriteLine("✓ User Authentication Systems");
    Console.WriteLine("✓ Role-Based Access Control");
    Console.WriteLine("\n📁 Files: Activities/Activity2_Authentication/");
    Console.WriteLine("📖 Guide: Activities/Activity2_Authentication/COMPLETION_GUIDE.md");
    Console.WriteLine("🔧 Tools: Password strength checker, hash generators");
}

static void ShowActivity3()
{
    Console.WriteLine("\n🚀 Activity 3: Advanced Security Features");
    Console.WriteLine("==========================================");
    Console.WriteLine("✓ API Rate Limiting");
    Console.WriteLine("✓ CSRF Protection");
    Console.WriteLine("✓ Security Headers & Best Practices");
    Console.WriteLine("\n📁 Files: Activities/Activity3_AdvancedSecurity/");
    Console.WriteLine("📖 Guide: Activities/Activity3_AdvancedSecurity/COMPLETION_GUIDE.md");
    Console.WriteLine("⚡ Advanced: JSON deserialization security, timing attacks");
}

static void ShowActivity4()
{
    Console.WriteLine("\n🔍 Activity 4: Debugging & Resolving Vulnerabilities");
    Console.WriteLine("=====================================================");
    Console.WriteLine("🧰 Using Microsoft Copilot for Security Debugging");
    Console.WriteLine("✓ Identify SQL Injection Vulnerabilities");
    Console.WriteLine("✓ Detect Cross-Site Scripting (XSS) Issues");
    Console.WriteLine("✓ Apply Security Fixes with Copilot Assistance");
    Console.WriteLine("✓ Generate Security Test Cases");
    Console.WriteLine("✓ Validate Fixes with Automated Testing");
    Console.WriteLine("\n📁 Files: Activities/Activity4_DebuggingVulnerabilities/");
    Console.WriteLine("📖 Guide: Activities/Activity4_DebuggingVulnerabilities/COMPLETION_GUIDE.md");
    Console.WriteLine("🔧 Examples: VulnerableCodeExamples.cs & SecureCodeExamples.cs");
    Console.WriteLine("🧪 Testing: SecurityTestSuite.cs");
    Console.WriteLine("\n💡 This is the final activity - complete security validation!");
    Console.WriteLine("🤖 Work with Copilot to identify, fix, and test security issues");
}

static void OpenWebInterface()
{
    Console.WriteLine("\n🌐 SafeVault Web Interface");
    Console.WriteLine("===========================");
    Console.WriteLine("The web interface provides interactive security testing:");
    Console.WriteLine("• Input validation testing forms");
    Console.WriteLine("• SQL injection demo environment");
    Console.WriteLine("• XSS prevention examples");
    Console.WriteLine("\n📂 Location: WebUI/index.html");
    Console.WriteLine("💡 Tip: Use VS Code's Live Server extension to host locally");
    Console.WriteLine("🔗 Or open directly in your browser");
}

/// <summary>
/// Interactive Security Demo - Hands-on testing of security implementations
/// This method demonstrates real security techniques with live examples
/// Automatically saves output to a timestamped file for analysis
/// </summary>
static async Task RunInteractiveSecurityDemo()
{
    Console.WriteLine("\n🔥 Interactive Security Demo");
    Console.WriteLine("============================");
    Console.WriteLine("This demo will test real security implementations with sample data\n");

    // Create output directory and file with timestamp
    var outputDir = Path.Combine(Directory.GetCurrentDirectory(), "SecurityDemoLogs");
    var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
    var logFile = Path.Combine(outputDir, $"SafeVault_Demo_{timestamp}.txt");
    
    var logger = new SecurityDemoLogger(logFile, allowOverwrite: true);

    try
    {
        // Demo 1: Input Validation & XSS Prevention
        Console.WriteLine("🛡️ Demo 1: Input Validation & XSS Prevention");
        Console.WriteLine("----------------------------------------------");
        await logger.LogSection("Demo 1: Input Validation & XSS Prevention");
        await TestInputValidation(logger);

        Console.WriteLine("\n" + new string('=', 50));

        // Demo 2: Password Security & Hashing
        Console.WriteLine("\n🔐 Demo 2: Password Security & Authentication");
        Console.WriteLine("----------------------------------------------");
        await logger.LogSection("Demo 2: Password Security & Authentication");
        await TestPasswordSecurity(logger);

        Console.WriteLine("\n" + new string('=', 50));

        // Demo 3: Advanced Security Features
        Console.WriteLine("\n🚀 Demo 3: Advanced Security Features");
        Console.WriteLine("--------------------------------------");
        await logger.LogSection("Demo 3: Advanced Security Features");
        await TestAdvancedSecurity(logger);

        Console.WriteLine("\n✅ Interactive demo completed!");
        Console.WriteLine("💡 Check the web interface for more interactive testing!");
        
        await logger.LogResult("✅ Interactive demo completed!");
        await logger.LogResult("💡 Check the web interface for more interactive testing!");
        
        Console.WriteLine($"\n📄 Demo output saved to: {logger.GetLogFilePath()}");
        Console.WriteLine("📊 Use this file for security analysis and learning review!");
        
        // Offer to open the log file
        Console.WriteLine("\nWould you like to open the log file? (y/n): ");
        var response = Console.ReadLine();
        if (response?.ToLower() == "y" || response?.ToLower() == "yes")
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = logger.GetLogFilePath(),
                    UseShellExecute = true
                });
                Console.WriteLine("Log file opened successfully!");
            }
            catch
            {
                Console.WriteLine("Could not open log file automatically. Please navigate to:");
                Console.WriteLine(logger.GetLogFilePath());
            }
        }
    }
    catch (Exception ex)
    {
        await logger.LogResult($"ERROR: {ex.Message}");
        Console.WriteLine($"An error occurred: {ex.Message}");
    }
}

/// <summary>
/// Test input validation and XSS prevention with real examples
/// Demonstrates both vulnerable and secure input handling
/// Logs all results to file for educational analysis
/// </summary>
static async Task TestInputValidation(SecurityDemoLogger logger)
{
    var validator = new InputValidator();
    
    // Test cases with actual malicious payloads used in real attacks
    var testInputs = new[]
    {
        ("Safe input", "Hello, SafeVault!"),
        ("XSS Script Tag", "<script>alert('XSS Attack!')</script>"),
        ("XSS Image Tag", "<img src=\"x\" onerror=\"alert('XSS')\" />"),
        ("SQL Injection", "'; DROP TABLE users; --"),
        ("Path Traversal", "../../../etc/passwd"),
        ("Command Injection", "; cat /etc/passwd")
    };

    Console.WriteLine("Testing various input types against security filters:\n");
    await logger.LogResult("Testing various input types against security filters:");

    foreach (var (description, input) in testInputs)
    {
        Console.WriteLine($"📝 Test: {description}");
        Console.WriteLine($"   Input: {input}");
        
        await logger.LogResult($"📝 Test: {description}");
        await logger.LogResult($"   Input: {input}");
        
        var result = validator.ValidateAndSanitize(input);
        
        if (result.IsSecure)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"   ✅ SECURE: {result.SanitizedInput}");
            await logger.LogResult($"   ✅ SECURE: {result.SanitizedInput}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"   ⚠️  THREAT DETECTED: {string.Join(", ", result.Threats)}");
            Console.WriteLine($"   🛡️  Sanitized: {result.SanitizedInput}");
            await logger.LogResult($"   ⚠️  THREAT DETECTED: {string.Join(", ", result.Threats)}");
            await logger.LogResult($"   🛡️  Sanitized: {result.SanitizedInput}");
        }
        
        Console.ResetColor();
        Console.WriteLine();
        await logger.LogResult("");
        
        // Add delay for educational purposes
        await Task.Delay(800);
    }
}

/// <summary>
/// Test password security implementations with real examples
/// Shows secure hashing, salt generation, and password strength analysis
/// Logs all results to file for educational analysis
/// </summary>
static async Task TestPasswordSecurity(SecurityDemoLogger logger)
{
    var passwordSecurity = new PasswordSecurity();
    
    // Real password examples from common breach databases
    var testPasswords = new[]
    {
        ("Weak", "password"),
        ("Common", "123456"),
        ("Moderate", "Password123"),
        ("Strong", "MyStr0ng!P@ssw0rd2024"),
        ("Very Strong", "Tr0ub4dor&3.Complex!Pass")
    };

    Console.WriteLine("Testing password security with real examples:\n");
    await logger.LogResult("Testing password security with real examples:");

    foreach (var (strength, password) in testPasswords)
    {
        Console.WriteLine($"🔑 Testing {strength} Password: {password}");
        await logger.LogResult($"🔑 Testing {strength} Password: {password}");
        
        // Generate unique salt for each password (security best practice)
        var salt = passwordSecurity.GenerateSalt();
        Console.WriteLine($"   🧂 Generated Salt: {salt[..16]}... (truncated for display)");
        await logger.LogResult($"   🧂 Generated Salt: {salt[..16]}... (truncated for display)");
        
        // Hash the password securely
        var hashedPassword = passwordSecurity.HashPassword(password, salt);
        Console.WriteLine($"   🔐 Hash: {hashedPassword[..32]}... (truncated for display)");
        await logger.LogResult($"   🔐 Hash: {hashedPassword[..32]}... (truncated for display)");
        
        // Test password strength
        var strengthScore = passwordSecurity.AnalyzePasswordStrength(password);
        
        Console.ForegroundColor = strengthScore.Score switch
        {
            >= 5 => ConsoleColor.Green,
            >= 3 => ConsoleColor.Yellow,
            _ => ConsoleColor.Red
        };
        
        Console.WriteLine($"   📊 Strength Score: {strengthScore.Score}/6");
        Console.WriteLine($"   💡 Feedback: {string.Join(", ", strengthScore.Recommendations)}");
        await logger.LogResult($"   📊 Strength Score: {strengthScore.Score}/6");
        await logger.LogResult($"   💡 Feedback: {string.Join(", ", strengthScore.Recommendations)}");
        
        // Verify password works correctly
        var isValid = passwordSecurity.VerifyPassword(password, hashedPassword, salt);
        Console.WriteLine($"   ✓ Verification Test: {(isValid ? "PASSED" : "FAILED")}");
        await logger.LogResult($"   ✓ Verification Test: {(isValid ? "PASSED" : "FAILED")}");
        
        Console.ResetColor();
        Console.WriteLine();
        await logger.LogResult("");
        
        await Task.Delay(1000);
    }
}

/// <summary>
/// Test advanced security features like rate limiting and CSRF protection
/// Demonstrates enterprise-level security implementations
/// Logs all results to file for educational analysis
/// </summary>
static async Task TestAdvancedSecurity(SecurityDemoLogger logger)
{
    Console.WriteLine("Testing enterprise security features:\n");
    await logger.LogResult("Testing enterprise security features:");

    // Test Rate Limiting
    Console.WriteLine("🚦 Rate Limiting Test");
    await logger.LogResult("🚦 Rate Limiting Test");
    var rateLimiter = new RateLimiter(maxRequests: 3, TimeSpan.FromSeconds(10));
    var clientId = "test-client-192.168.1.100";

    for (int i = 1; i <= 5; i++)
    {
        var allowed = rateLimiter.IsAllowed(clientId);
        var status = allowed ? "✅ ALLOWED" : "🚫 BLOCKED";
        var color = allowed ? ConsoleColor.Green : ConsoleColor.Red;
        
        Console.ForegroundColor = color;
        Console.WriteLine($"   Request #{i}: {status}");
        await logger.LogResult($"   Request #{i}: {status}");
        Console.ResetColor();
        
        await Task.Delay(500);
    }

    Console.WriteLine();
    await logger.LogResult("");

    // Test CSRF Protection
    Console.WriteLine("🛡️ CSRF Protection Test");
    await logger.LogResult("🛡️ CSRF Protection Test");
    var csrfProtection = new CSRFProtection();
    var sessionId = "user-session-abc123";
    
    var token = csrfProtection.GenerateCSRFToken(sessionId);
    Console.WriteLine($"   🎫 Generated Token: {token[..20]}... (truncated)");
    await logger.LogResult($"   🎫 Generated Token: {token[..20]}... (truncated)");
    
    var isValidToken = csrfProtection.ValidateCSRFToken(token, sessionId);
    Console.ForegroundColor = isValidToken ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine($"   ✓ Token Validation: {(isValidToken ? "VALID" : "INVALID")}");
    await logger.LogResult($"   ✓ Token Validation: {(isValidToken ? "VALID" : "INVALID")}");
    Console.ResetColor();

    Console.WriteLine();
    await logger.LogResult("");

    // Test Timing Attack Prevention
    Console.WriteLine("⏱️ Timing Attack Prevention Test");
    await logger.LogResult("⏱️ Timing Attack Prevention Test");
    var secureComparison = new SecureComparison();
    
    var correctPassword = "super-secret-password";
    var testPasswords = new[] { "super-secret-password", "wrong-password", "super" };

    foreach (var testPwd in testPasswords)
    {
        var stopwatch = Stopwatch.StartNew();
        var isMatch = await secureComparison.AuthenticateWithDelay(testPwd, correctPassword);
        stopwatch.Stop();
        
        var color = isMatch ? ConsoleColor.Green : ConsoleColor.Red;
        Console.ForegroundColor = color;
        var result = $"   Test '{testPwd}': {(isMatch ? "MATCH" : "NO MATCH")} ({stopwatch.ElapsedMilliseconds}ms)";
        Console.WriteLine(result);
        await logger.LogResult(result);
        Console.ResetColor();
    }

    Console.WriteLine();
    await logger.LogResult("");

    // Test Security Headers Analysis
    Console.WriteLine("🛡️ Security Headers Analysis Test");
    await logger.LogResult("🛡️ Security Headers Analysis Test");
    
    var headerChecker = new SecurityHeadersChecker();
    
    // Simulate sample headers (in production, these would come from HTTP response)
    var sampleHeaders = new Dictionary<string, string>
    {
        ["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'",
        ["X-Frame-Options"] = "SAMEORIGIN",
        ["X-Content-Type-Options"] = "nosniff",
        // Missing some critical headers for educational purposes
    };
    
    Console.WriteLine("   🔍 Analyzing security headers configuration...");
    await logger.LogResult("   🔍 Analyzing security headers configuration...");
    
    var analysis = headerChecker.AnalyzeHeaders(sampleHeaders);
    
    Console.WriteLine($"   📊 Overall Security Rating: {analysis.OverallRating}");
    Console.WriteLine($"   🏆 Security Score: {analysis.SecurityScorePercentage}%");
    await logger.LogResult($"   📊 Overall Security Rating: {analysis.OverallRating}");
    await logger.LogResult($"   🏆 Security Score: {analysis.SecurityScorePercentage}%");
    
    // Show top security issues
    var criticalIssues = analysis.HeaderChecks
        .Where(c => c.Header.Importance <= SecurityHeadersChecker.SecurityLevel.High && !c.IsConfiguredProperly)
        .Take(3);
    
    Console.WriteLine("   🚨 Top Security Recommendations:");
    await logger.LogResult("   🚨 Top Security Recommendations:");
    
    foreach (var issue in criticalIssues)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"      • {issue.Recommendation}");
        Console.WriteLine($"        Purpose: {issue.Header.Purpose}");
        await logger.LogResult($"      • {issue.Recommendation}");
        await logger.LogResult($"        Purpose: {issue.Header.Purpose}");
        Console.ResetColor();
    }
}

/// <summary>
/// SecurityDemoLogger - Handles automatic logging of security demonstration output
/// Educational: Provides audit trail and file-based output for analysis
/// </summary>
public class SecurityDemoLogger
{
    private readonly string _logFilePath;
    private readonly bool _allowOverwrite;

    /// <summary>
    /// Initialize logger with specified file path and overwrite policy
    /// </summary>
    /// <param name="logFilePath">Path to the log file</param>
    /// <param name="allowOverwrite">Whether to overwrite existing file or append</param>
    public SecurityDemoLogger(string logFilePath, bool allowOverwrite = true)
    {
        _logFilePath = logFilePath;
        _allowOverwrite = allowOverwrite;
        
        // Create directory if it doesn't exist
        var directory = Path.GetDirectoryName(_logFilePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }
        
        // Initialize log file
        InitializeLogFile();
    }

    /// <summary>
    /// Initialize or clear the log file
    /// </summary>
    private void InitializeLogFile()
    {
        if (_allowOverwrite || !File.Exists(_logFilePath))
        {
            using var writer = new StreamWriter(_logFilePath, false);
            writer.WriteLine($"SafeVault Security Demo Log");
            writer.WriteLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            writer.WriteLine($"Session: {Guid.NewGuid()}");
            writer.WriteLine(new string('=', 60));
            writer.WriteLine();
        }
    }

    /// <summary>
    /// Log a result to the file asynchronously
    /// </summary>
    /// <param name="result">The result text to log</param>
    public async Task LogResult(string result)
    {
        try
        {
            using var writer = new StreamWriter(_logFilePath, true);
            await writer.WriteLineAsync($"[{DateTime.Now:HH:mm:ss}] {result}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not write to log file: {ex.Message}");
        }
    }

    /// <summary>
    /// Log multiple results at once
    /// </summary>
    /// <param name="results">Array of results to log</param>
    public async Task LogResults(string[] results)
    {
        foreach (var result in results)
        {
            await LogResult(result);
        }
    }

    /// <summary>
    /// Add a section header to the log
    /// </summary>
    /// <param name="sectionTitle">Title of the section</param>
    public async Task LogSection(string sectionTitle)
    {
        await LogResult("");
        await LogResult(new string('-', 40));
        await LogResult($"SECTION: {sectionTitle.ToUpper()}");
        await LogResult(new string('-', 40));
        await LogResult("");
    }

    /// <summary>
    /// Get the full path of the log file
    /// </summary>
    public string GetLogFilePath() => _logFilePath;
}

/// <summary>
/// SecurityHeadersChecker - Comprehensive HTTP security headers analyzer
/// Educational: Demonstrates critical security headers and their importance
/// </summary>
public class SecurityHeadersChecker
{
    /// <summary>
    /// Security header configurations with descriptions and examples
    /// </summary>
    public class SecurityHeader
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string RecommendedValue { get; set; } = "";
        public string Purpose { get; set; } = "";
        public SecurityLevel Importance { get; set; }
    }

    public enum SecurityLevel
    {
        Critical = 1,
        High = 2, 
        Medium = 3,
        Low = 4
    }

    /// <summary>
    /// Get all recommended security headers with explanations
    /// </summary>
    public List<SecurityHeader> GetRecommendedSecurityHeaders()
    {
        return new List<SecurityHeader>
        {
            new SecurityHeader
            {
                Name = "Content-Security-Policy",
                Description = "Prevents XSS attacks by controlling which resources can be loaded",
                RecommendedValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                Purpose = "XSS Prevention, Code Injection Protection",
                Importance = SecurityLevel.Critical
            },
            new SecurityHeader
            {
                Name = "Strict-Transport-Security",
                Description = "Enforces HTTPS connections and prevents downgrade attacks",
                RecommendedValue = "max-age=31536000; includeSubDomains; preload",
                Purpose = "MITM Prevention, SSL Stripping Protection",
                Importance = SecurityLevel.Critical
            },
            new SecurityHeader
            {
                Name = "X-Frame-Options",
                Description = "Prevents clickjacking attacks by controlling iframe embedding",
                RecommendedValue = "DENY or SAMEORIGIN",
                Purpose = "Clickjacking Prevention",
                Importance = SecurityLevel.High
            },
            new SecurityHeader
            {
                Name = "X-Content-Type-Options",
                Description = "Prevents MIME type sniffing attacks",
                RecommendedValue = "nosniff",
                Purpose = "MIME Sniffing Prevention",
                Importance = SecurityLevel.High
            },
            new SecurityHeader
            {
                Name = "Referrer-Policy",
                Description = "Controls referrer information sent with requests",
                RecommendedValue = "strict-origin-when-cross-origin",
                Purpose = "Privacy Protection, Information Disclosure Prevention",
                Importance = SecurityLevel.Medium
            },
            new SecurityHeader
            {
                Name = "X-XSS-Protection",
                Description = "Legacy XSS filter (deprecated but still useful for older browsers)",
                RecommendedValue = "1; mode=block",
                Purpose = "XSS Prevention (Legacy)",
                Importance = SecurityLevel.Medium
            },
            new SecurityHeader
            {
                Name = "Permissions-Policy",
                Description = "Controls browser features and APIs available to the page",
                RecommendedValue = "camera=(), microphone=(), geolocation=()",
                Purpose = "Feature Control, Privacy Protection",
                Importance = SecurityLevel.Medium
            },
            new SecurityHeader
            {
                Name = "Cross-Origin-Embedder-Policy",
                Description = "Controls cross-origin resource embedding",
                RecommendedValue = "require-corp",
                Purpose = "Cross-Origin Attack Prevention",
                Importance = SecurityLevel.Low
            },
            new SecurityHeader
            {
                Name = "Cross-Origin-Opener-Policy",
                Description = "Controls cross-origin window interactions",
                RecommendedValue = "same-origin",
                Purpose = "Cross-Origin Attack Prevention",
                Importance = SecurityLevel.Low
            },
            new SecurityHeader
            {
                Name = "Cross-Origin-Resource-Policy",
                Description = "Controls cross-origin resource access",
                RecommendedValue = "same-origin",
                Purpose = "Cross-Origin Attack Prevention",
                Importance = SecurityLevel.Low
            }
        };
    }

    /// <summary>
    /// Analyze security headers and provide recommendations
    /// </summary>
    public SecurityHeadersAnalysis AnalyzeHeaders(Dictionary<string, string> headers)
    {
        var analysis = new SecurityHeadersAnalysis();
        var recommendedHeaders = GetRecommendedSecurityHeaders();
        
        foreach (var recommended in recommendedHeaders)
        {
            var headerExists = headers.ContainsKey(recommended.Name);
            var headerValue = headerExists ? headers[recommended.Name] : "";
            
            var headerCheck = new SecurityHeaderCheck
            {
                Header = recommended,
                IsPresent = headerExists,
                CurrentValue = headerValue,
                IsConfiguredProperly = headerExists && IsProperlyConfigured(recommended, headerValue),
                Recommendation = GetRecommendation(recommended, headerExists, headerValue)
            };
            
            analysis.HeaderChecks.Add(headerCheck);
            
            // Calculate security score
            if (headerCheck.IsConfiguredProperly)
            {
                analysis.SecurityScore += (int)recommended.Importance;
            }
        }
        
        // Calculate percentage (lower importance number = higher weight)
        var maxScore = recommendedHeaders.Sum(h => (int)h.Importance);
        analysis.SecurityScorePercentage = (int)((double)analysis.SecurityScore / maxScore * 100);
        analysis.OverallRating = GetOverallRating(analysis.SecurityScorePercentage);
        
        return analysis;
    }

    private bool IsProperlyConfigured(SecurityHeader header, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        
        return header.Name switch
        {
            "Content-Security-Policy" => value.Contains("default-src") && !value.Contains("'unsafe-eval'"),
            "Strict-Transport-Security" => value.Contains("max-age=") && int.TryParse(value.Split('=')[1].Split(';')[0], out var maxAge) && maxAge >= 31536000,
            "X-Frame-Options" => value.ToUpper() is "DENY" or "SAMEORIGIN",
            "X-Content-Type-Options" => value.ToLower() == "nosniff",
            "Referrer-Policy" => !string.IsNullOrEmpty(value),
            "X-XSS-Protection" => value.StartsWith("1"),
            _ => !string.IsNullOrEmpty(value)
        };
    }

    private string GetRecommendation(SecurityHeader header, bool isPresent, string value)
    {
        if (!isPresent)
        {
            return $"❌ ADD: {header.Name} = {header.RecommendedValue}";
        }
        
        if (!IsProperlyConfigured(header, value))
        {
            return $"⚠️ IMPROVE: Current: '{value}' → Recommended: '{header.RecommendedValue}'";
        }
        
        return "✅ GOOD: Header is properly configured";
    }

    private string GetOverallRating(int percentage)
    {
        return percentage switch
        {
            >= 90 => "🛡️ EXCELLENT",
            >= 80 => "✅ GOOD", 
            >= 70 => "⚠️ MODERATE",
            >= 50 => "❌ POOR",
            _ => "🚨 CRITICAL"
        };
    }
}

/// <summary>
/// Security headers analysis result
/// </summary>
public class SecurityHeadersAnalysis
{
    public List<SecurityHeaderCheck> HeaderChecks { get; set; } = new();
    public int SecurityScore { get; set; }
    public int SecurityScorePercentage { get; set; }
    public string OverallRating { get; set; } = "";
}

/// <summary>
/// Individual security header check result
/// </summary>
public class SecurityHeaderCheck
{
    public SecurityHeadersChecker.SecurityHeader Header { get; set; } = new();
    public bool IsPresent { get; set; }
    public string CurrentValue { get; set; } = "";
    public bool IsConfiguredProperly { get; set; }
    public string Recommendation { get; set; } = "";
}

#region Security Implementation Classes

/// <summary>
/// Input Validator - Demonstrates secure input handling and XSS prevention
/// Educational: Shows both detection and sanitization of malicious inputs
/// </summary>
public class InputValidator
{
    /// <summary>
    /// Validates and sanitizes user input against common attack vectors
    /// Returns both the sanitized input and detected threats for educational purposes
    /// </summary>
    public ValidationResult ValidateAndSanitize(string input)
    {
        var result = new ValidationResult { SanitizedInput = input };
        
        if (string.IsNullOrWhiteSpace(input))
        {
            result.Threats.Add("Empty input detected");
            result.IsSecure = false;
            return result;
        }

        // Check for XSS patterns - Common attack vectors from OWASP
        var xssPatterns = new Dictionary<string, string>
        {
            [@"<script.*?>.*?</script>"] = "Script tag injection",
            [@"javascript:"] = "JavaScript protocol handler",
            [@"on\w+\s*="] = "Event handler injection", 
            [@"<iframe.*?>"] = "Iframe injection",
            [@"<object.*?>"] = "Object tag injection"
        };

        foreach (var (pattern, threat) in xssPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                result.Threats.Add($"XSS: {threat}");
                result.IsSecure = false;
            }
        }

        // Check for SQL Injection patterns - Real attack signatures
        var sqlPatterns = new Dictionary<string, string>
        {
            [@"['""`;]|(\-\-)"] = "SQL metacharacters",
            [@"\b(union|select|insert|update|delete|drop|create|alter)\b"] = "SQL keywords",
            [@"\b(or|and)\b.*[=<>]"] = "Logic manipulation",
            [@"1\s*=\s*1"] = "Always-true condition"
        };

        foreach (var (pattern, threat) in sqlPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                result.Threats.Add($"SQL Injection: {threat}");
                result.IsSecure = false;
            }
        }

        // Check for Path Traversal - Directory traversal attacks
        if (Regex.IsMatch(input, @"\.\.\/|\.\.\\", RegexOptions.IgnoreCase))
        {
            result.Threats.Add("Path Traversal: Directory navigation attempt");
            result.IsSecure = false;
        }

        // Check for Command Injection
        if (Regex.IsMatch(input, @";|\||&|`|\$\(", RegexOptions.IgnoreCase))
        {
            result.Threats.Add("Command Injection: Shell command separators");
            result.IsSecure = false;
        }

        // Sanitize the input using HTML encoding (secure approach)
        result.SanitizedInput = HtmlEncode(input);
        
        return result;
    }

    /// <summary>
    /// HTML encode function - Converts dangerous characters to safe entities
    /// This is the primary defense against XSS attacks
    /// </summary>
    private string HtmlEncode(string input) => input
        .Replace("&", "&amp;")   // Must be first to avoid double-encoding
        .Replace("<", "&lt;")    // Prevents tag injection
        .Replace(">", "&gt;")    // Prevents tag injection  
        .Replace("\"", "&quot;") // Prevents attribute injection
        .Replace("'", "&#x27;")  // Prevents attribute injection
        .Replace("/", "&#x2F;"); // Additional safety for URLs
}

/// <summary>
/// Validation Result - Contains both sanitized input and threat analysis
/// Educational: Helps learners understand what was detected and why
/// </summary>
public class ValidationResult
{
    public bool IsSecure { get; set; } = true;
    public string SanitizedInput { get; set; } = "";
    public List<string> Threats { get; set; } = new();
}

/// <summary>
/// Password Security - Demonstrates industry-standard password handling
/// Educational: Shows secure hashing, salting, and strength analysis
/// </summary>
public class PasswordSecurity
{
    /// <summary>
    /// Generate cryptographically secure salt - Unique for each password
    /// Why: Prevents rainbow table attacks and ensures identical passwords have different hashes
    /// </summary>
    public string GenerateSalt()
    {
        using var rng = RandomNumberGenerator.Create();
        var saltBytes = new byte[32]; // 256-bit salt for maximum security
        rng.GetBytes(saltBytes);
        return Convert.ToBase64String(saltBytes);
    }

    /// <summary>
    /// Hash password with salt using SHA-256
    /// Educational: In production, use bcrypt, Argon2, or PBKDF2 for better security
    /// </summary>
    public string HashPassword(string password, string salt)
    {
        using var sha256 = SHA256.Create();
        var saltedPassword = password + salt; // Concatenate password and salt
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword));
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Verify password against stored hash - Constant-time comparison
    /// Security: Uses the same hashing process to compare results
    /// </summary>
    public bool VerifyPassword(string password, string storedHash, string salt)
    {
        var computedHash = HashPassword(password, salt);
        return SecureStringEquals(computedHash, storedHash);
    }

    /// <summary>
    /// Secure string comparison - Prevents timing attacks
    /// Why: Normal string comparison can leak information about password length/content
    /// </summary>
    private bool SecureStringEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        
        int result = 0;
        for (int i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i]; // XOR operation - constant time
        }
        return result == 0;
    }

    /// <summary>
    /// Analyze password strength - Educational scoring system
    /// Implements NIST and OWASP password guidelines
    /// </summary>
    public PasswordStrengthResult AnalyzePasswordStrength(string password)
    {
        var result = new PasswordStrengthResult();
        
        // Length requirements (NIST recommends 8+ characters minimum)
        if (password.Length >= 8) result.Score++;
        else result.Recommendations.Add("Use at least 8 characters");
        
        if (password.Length >= 12) result.Score++; // Bonus for longer passwords
        
        // Character diversity requirements
        if (Regex.IsMatch(password, @"[a-z]")) result.Score++;
        else result.Recommendations.Add("Include lowercase letters");
        
        if (Regex.IsMatch(password, @"[A-Z]")) result.Score++;
        else result.Recommendations.Add("Include uppercase letters");
        
        if (Regex.IsMatch(password, @"[0-9]")) result.Score++;
        else result.Recommendations.Add("Include numbers");
        
        if (Regex.IsMatch(password, @"[^A-Za-z0-9]")) result.Score++;
        else result.Recommendations.Add("Include special characters (!@#$%^&*)");
        
        // Penalty for common patterns (security weakness)
        if (Regex.IsMatch(password, @"(.)\1{2,}")) // Repeated characters
        {
            result.Score--;
            result.Recommendations.Add("Avoid repeating characters (aaa, 111)");
        }
        
        // Check against common passwords (simplified list for demo)
        var commonPasswords = new[] { "password", "123456", "qwerty", "admin", "letmein" };
        if (commonPasswords.Any(common => password.ToLower().Contains(common)))
        {
            result.Score--;
            result.Recommendations.Add("Avoid common password patterns");
        }
        
        return result;
    }
}

/// <summary>
/// Password Strength Result - Detailed analysis for educational purposes
/// Helps users understand password security requirements
/// </summary>
public class PasswordStrengthResult
{
    public int Score { get; set; } = 0;
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>
/// Rate Limiter - Implements sliding window algorithm for DDoS protection
/// Educational: Shows how to prevent brute force and abuse attacks
/// </summary>
public class RateLimiter
{
    private readonly Dictionary<string, Queue<DateTime>> _requests = new();
    private readonly int _maxRequests;
    private readonly TimeSpan _timeWindow;

    /// <summary>
    /// Initialize rate limiter with specific limits
    /// Example: 100 requests per hour, 5 requests per minute
    /// </summary>
    public RateLimiter(int maxRequests, TimeSpan timeWindow)
    {
        _maxRequests = maxRequests;
        _timeWindow = timeWindow;
    }

    /// <summary>
    /// Check if client is allowed to make request - Sliding window implementation
    /// Why: More accurate than fixed windows, prevents burst attacks at window boundaries
    /// </summary>
    public bool IsAllowed(string clientId)
    {
        var now = DateTime.UtcNow;
        
        // Initialize client tracking if first request
        if (!_requests.ContainsKey(clientId))
        {
            _requests[clientId] = new Queue<DateTime>();
        }
        
        var clientRequests = _requests[clientId];
        
        // Remove expired requests (sliding window cleanup)
        while (clientRequests.Count > 0 && now - clientRequests.Peek() > _timeWindow)
        {
            clientRequests.Dequeue();
        }
        
        // Check if limit would be exceeded
        if (clientRequests.Count >= _maxRequests)
        {
            return false; // Rate limit exceeded
        }
        
        // Add current request and allow
        clientRequests.Enqueue(now);
        return true;
    }
}

/// <summary>
/// CSRF Protection - Cross-Site Request Forgery prevention
/// Educational: Shows how to prevent unauthorized actions from malicious sites
/// </summary>
public class CSRFProtection
{
    private const string SecretKey = "SafeVault-CSRF-Secret-Key-2024"; // In production: use secure key storage

    /// <summary>
    /// Generate CSRF token with HMAC signature and timestamp
    /// Why: Cryptographically secure, time-limited, tied to user session
    /// </summary>
    public string GenerateCSRFToken(string sessionId)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SecretKey));
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var data = $"{sessionId}:{timestamp}";
        var signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        
        return $"{timestamp}:{Convert.ToBase64String(signature)}";
    }

    /// <summary>
    /// Validate CSRF token - Prevents replay and tampering attacks
    /// Security: Checks signature, timestamp, and session binding
    /// </summary>
    public bool ValidateCSRFToken(string token, string sessionId, int maxAgeSeconds = 3600)
    {
        try
        {
            var parts = token.Split(':');
            if (parts.Length != 2) return false;
            
            var timestamp = long.Parse(parts[0]);
            var providedSignature = parts[1];
            
            // Check token age (prevents replay attacks)
            var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp;
            if (age > maxAgeSeconds) return false;
            
            // Recreate signature and compare
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SecretKey));
            var data = $"{sessionId}:{timestamp}";
            var expectedSignature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
            
            return SecureStringEquals(expectedSignature, providedSignature);
        }
        catch
        {
            return false; // Invalid token format
        }
    }

    /// <summary>
    /// Secure string comparison to prevent timing attacks on token validation
    /// </summary>
    private bool SecureStringEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        
        int result = 0;
        for (int i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}

/// <summary>
/// Secure Comparison - Timing attack prevention for authentication
/// Educational: Shows why constant-time operations matter in security
/// </summary>
public class SecureComparison
{
    /// <summary>
    /// Authenticate with consistent timing - Prevents timing analysis attacks
    /// Why: Variable timing can leak information about password correctness
    /// </summary>
    public async Task<bool> AuthenticateWithDelay(string provided, string expected)
    {
        var stopwatch = Stopwatch.StartNew();
        
        // Perform constant-time comparison
        bool isValid = ConstantTimeEquals(provided, expected);
        
        // Ensure minimum processing time (prevents timing attacks)
        const int minDelayMs = 100;
        var remaining = minDelayMs - (int)stopwatch.ElapsedMilliseconds;
        if (remaining > 0)
        {
            await Task.Delay(remaining); // Constant total time regardless of input
        }
        
        return isValid;
    }

    /// <summary>
    /// Constant-time string equality check - Core security primitive
    /// Algorithm: XOR all characters and check if result is zero
    /// </summary>
    private bool ConstantTimeEquals(string a, string b)
    {
        if (a == null || b == null) return false;
        
        // XOR length difference (non-zero if lengths differ)
        int diff = a.Length ^ b.Length;
        
        // XOR all characters (processes both strings completely)
        for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            int aChar = i < a.Length ? a[i] : 0;
            int bChar = i < b.Length ? b[i] : 0;
            diff |= aChar ^ bChar; // Accumulate differences
        }
        
        return diff == 0; // True only if no differences found
    }
}

#endregion
