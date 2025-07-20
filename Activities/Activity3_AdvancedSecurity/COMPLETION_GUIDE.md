# Activity 3: Advanced Security Features - Completion Guide

## 🎯 Learning Objectives
By completing this activity, you will understand:
- API rate limiting and DDoS protection
- CSRF (Cross-Site Request Forgery) prevention
- Security headers implementation
- Timing attack prevention
- Advanced threat detection

## 📋 Activity Tasks

### Task 1: Security Headers Analysis
1. **Use the Web Interface Security Checker**:
   - Review the security headers analysis
   - Understand each header's purpose
   - Learn about CSP (Content Security Policy)

### Task 2: Rate Limiting Implementation
```csharp
// Rate limiting with sliding window
public class RateLimiter
{
    private readonly Dictionary<string, Queue<DateTime>> _requests = new();
    private readonly int _maxRequests;
    private readonly TimeSpan _timeWindow;
    
    public RateLimiter(int maxRequests, TimeSpan timeWindow)
    {
        _maxRequests = maxRequests;
        _timeWindow = timeWindow;
    }
    
    public bool IsAllowed(string clientId)
    {
        var now = DateTime.UtcNow;
        
        if (!_requests.ContainsKey(clientId))
        {
            _requests[clientId] = new Queue<DateTime>();
        }
        
        var clientRequests = _requests[clientId];
        
        // Remove old requests outside the time window
        while (clientRequests.Count > 0 && now - clientRequests.Peek() > _timeWindow)
        {
            clientRequests.Dequeue();
        }
        
        // Check if limit exceeded
        if (clientRequests.Count >= _maxRequests)
        {
            return false;
        }
        
        // Add current request
        clientRequests.Enqueue(now);
        return true;
    }
}
```

### Task 3: CSRF Protection
```csharp
// CSRF token generation and validation
public class CSRFProtection
{
    public static string GenerateCSRFToken(string sessionId)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("your-secret-key")))
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var data = $"{sessionId}:{timestamp}";
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return $"{timestamp}:{Convert.ToBase64String(hash)}";
        }
    }
    
    public static bool ValidateCSRFToken(string token, string sessionId, int maxAgeSeconds = 3600)
    {
        try
        {
            var parts = token.Split(':');
            if (parts.Length != 2) return false;
            
            var timestamp = long.Parse(parts[0]);
            var providedHash = parts[1];
            
            // Check age
            var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp;
            if (age > maxAgeSeconds) return false;
            
            // Regenerate hash
            var data = $"{sessionId}:{timestamp}";
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("your-secret-key")))
            {
                var expectedHash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
                return expectedHash == providedHash;
            }
        }
        catch
        {
            return false;
        }
    }
}
```

### Task 4: Timing Attack Prevention
```csharp
// Constant-time string comparison
public static class SecureComparison
{
    public static bool ConstantTimeEquals(string a, string b)
    {
        if (a == null || b == null) return false;
        
        int diff = a.Length ^ b.Length;
        for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            int aChar = i < a.Length ? a[i] : 0;
            int bChar = i < b.Length ? b[i] : 0;
            diff |= aChar ^ bChar;
        }
        
        return diff == 0;
    }
    
    public static async Task<bool> AuthenticateWithDelay(string provided, string expected)
    {
        // Add consistent delay to prevent timing attacks
        var sw = Stopwatch.StartNew();
        bool isValid = ConstantTimeEquals(provided, expected);
        
        // Ensure minimum processing time
        const int minDelayMs = 100;
        var remaining = minDelayMs - (int)sw.ElapsedMilliseconds;
        if (remaining > 0)
        {
            await Task.Delay(remaining);
        }
        
        return isValid;
    }
}
```

### Task 5: Advanced Input Validation
```csharp
// Comprehensive input validation
public class InputValidator
{
    public static ValidationResult ValidateInput(string input, InputType type)
    {
        var result = new ValidationResult();
        
        // Common validation
        if (string.IsNullOrWhiteSpace(input))
        {
            result.AddError("Input cannot be empty");
            return result;
        }
        
        // Type-specific validation
        switch (type)
        {
            case InputType.Email:
                ValidateEmail(input, result);
                break;
            case InputType.URL:
                ValidateURL(input, result);
                break;
            case InputType.JSON:
                ValidateJSON(input, result);
                break;
            case InputType.SQL:
                ValidateSQL(input, result);
                break;
        }
        
        // Security checks
        CheckForMaliciousPatterns(input, result);
        
        return result;
    }
    
    private static void CheckForMaliciousPatterns(string input, ValidationResult result)
    {
        var patterns = new[]
        {
            @"<script.*?>.*?</script>", // XSS
            @"javascript:", // XSS
            @"union.*select", // SQL injection
            @"drop.*table", // SQL injection
            @"\.\.\/", // Path traversal
            @"cmd\.exe|powershell", // Command injection
        };
        
        foreach (var pattern in patterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                result.AddSecurityViolation($"Potentially malicious pattern detected: {pattern}");
            }
        }
    }
}
```

## 🔍 Key Security Concepts Learned

### Security Headers
- **Content-Security-Policy**: Controls resource loading
- **X-Frame-Options**: Prevents clickjacking
- **Strict-Transport-Security**: Enforces HTTPS
- **X-Content-Type-Options**: Prevents MIME sniffing

### Rate Limiting
- **Token Bucket**: Fixed rate with burst allowance
- **Sliding Window**: Dynamic rate calculation
- **Distributed**: Coordination across servers

### CSRF Protection
- **Synchronizer Tokens**: Unique per session/form
- **Double Submit Cookie**: Token in cookie and form
- **SameSite Cookies**: Browser-level protection

## ✅ Completion Checklist
- [ ] Analyzed security headers and their purposes
- [ ] Implemented rate limiting with sliding window
- [ ] Created CSRF token generation and validation
- [ ] Understood timing attack prevention techniques
- [ ] Built comprehensive input validation system
- [ ] Can explain advanced security concepts

## 🚀 Advanced Challenges
1. **Implement JWT (JSON Web Token)** with proper validation
2. **Create honeypot fields** for bot detection
3. **Add IP reputation checking** for threat detection
4. **Implement WebAuthn** for passwordless authentication
5. **Create security event correlation** system

## 📚 Additional Resources
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Security Headers Guide](https://securityheaders.com/)
- [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Rate Limiting Strategies](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)

## 🏆 Assessment
You have successfully completed Activity 3 when you can:
- Implement and configure security headers properly
- Create effective rate limiting systems
- Understand and prevent CSRF attacks
- Implement timing-safe operations
- Design comprehensive threat detection systems
- Apply advanced security patterns in real applications
