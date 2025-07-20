# Activity 2: Authentication & Authorization - Completion Guide

## 🎯 Learning Objectives
By completing this activity, you will understand:
- Secure password hashing techniques
- Multi-factor authentication implementation
- Session management best practices
- Role-based access control (RBAC)

## 📋 Activity Tasks

### Task 1: Password Security Analysis
1. **Use the Web Interface Password Checker**:
   - Test weak passwords: "password", "123456", "admin"
   - Test medium passwords: "Password123"
   - Test strong passwords: "MyStr0ng!P@ssw0rd2024"
   - Understand the scoring system

### Task 2: Password Hashing Implementation
```csharp
// Secure password hashing example
using System.Security.Cryptography;
using System.Text;

public class PasswordSecurity
{
    public static string HashPassword(string password, string salt)
    {
        using (var sha256 = SHA256.Create())
        {
            var saltedPassword = password + salt;
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword));
            return Convert.ToBase64String(bytes);
        }
    }
    
    public static string GenerateSalt()
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            var saltBytes = new byte[32];
            rng.GetBytes(saltBytes);
            return Convert.ToBase64String(saltBytes);
        }
    }
    
    public static bool VerifyPassword(string password, string hash, string salt)
    {
        var hashToVerify = HashPassword(password, salt);
        return hashToVerify.Equals(hash);
    }
}
```

### Task 3: Session Management Security
```csharp
// Secure session implementation
public class SecureSession
{
    public static string GenerateSessionToken()
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            var tokenBytes = new byte[32];
            rng.GetBytes(tokenBytes);
            return Convert.ToBase64String(tokenBytes);
        }
    }
    
    public static bool ValidateSession(string token, DateTime createdAt)
    {
        // Session timeout (30 minutes)
        if (DateTime.UtcNow.Subtract(createdAt).TotalMinutes > 30)
        {
            return false;
        }
        
        // Token format validation
        if (string.IsNullOrEmpty(token) || token.Length != 44)
        {
            return false;
        }
        
        return true;
    }
}
```

### Task 4: Role-Based Access Control
```csharp
// RBAC implementation example
public enum UserRole
{
    Guest = 0,
    User = 1,
    Moderator = 2,
    Administrator = 3
}

public class AccessControl
{
    public static bool HasPermission(UserRole userRole, string action)
    {
        var permissions = new Dictionary<UserRole, HashSet<string>>
        {
            [UserRole.Guest] = new HashSet<string> { "view_public" },
            [UserRole.User] = new HashSet<string> { "view_public", "view_profile", "edit_profile" },
            [UserRole.Moderator] = new HashSet<string> { "view_public", "view_profile", "edit_profile", "moderate_content" },
            [UserRole.Administrator] = new HashSet<string> { "view_public", "view_profile", "edit_profile", "moderate_content", "manage_users", "system_admin" }
        };
        
        return permissions.ContainsKey(userRole) && permissions[userRole].Contains(action);
    }
}
```

## 🔍 Key Security Concepts Learned

### Password Security
- **Hashing vs Encryption**: One-way vs two-way processes
- **Salt**: Unique random value per password
- **Work Factor**: Computational cost to slow brute force
- **Password Policies**: Length, complexity requirements

### Session Management
- **Secure Tokens**: Cryptographically random session IDs
- **Session Timeout**: Automatic expiration
- **Session Regeneration**: New ID after login
- **Secure Cookies**: HttpOnly, Secure, SameSite flags

### Authentication Factors
- **Something you know**: Password, PIN
- **Something you have**: Phone, hardware token
- **Something you are**: Biometrics

## ✅ Completion Checklist
- [ ] Tested password strength checker with various inputs
- [ ] Implemented secure password hashing with salts
- [ ] Understanding session token generation and validation
- [ ] Created role-based access control system
- [ ] Can explain the difference between authentication and authorization
- [ ] Knows how to implement secure session management

## 🚀 Advanced Challenges
1. **Implement TOTP (Time-based One-Time Password)** for 2FA
2. **Create password breach checking** against known compromised passwords
3. **Add OAuth 2.0 integration** with external providers
4. **Implement account lockout mechanism** with exponential backoff

## 📚 Additional Resources
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Session Management Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

## 🏆 Assessment
You have successfully completed Activity 2 when you can:
- Implement secure password hashing with individual salts
- Create and validate secure session tokens
- Design role-based access control systems
- Explain multi-factor authentication concepts
- Implement proper session timeout and regeneration
