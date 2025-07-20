# 🔐 SafeVault Security Learning Platform

SafeVault is a comprehensive cybersecurity education platform designed to teach secure coding practices through hands-on activities and interactive demonstrations.

## 🎯 Project Overview

SafeVault provides a structured learning environment where developers can:
- Learn about common security vulnerabilities
- Practice secure coding techniques
- Test security implementations interactively
- Understand real-world attack and defense scenarios

## 🚀 Quick Start

### Prerequisites
- .NET 8.0 SDK or later
- Web browser (for interactive demos)
- VS Code with Live Server extension (recommended)

### Running SafeVault

1. **Console Application**:
   ```bash
   dotnet run
   ```

2. **Interactive Security Demo**:
   ```bash
   # Windows PowerShell
   .\demo.ps1
   
   # Or run directly
   dotnet run
   # Then select option 5
   ```

3. **Web Interface**:
   - Open `WebUI/index.html` in your browser
   - Or use VS Code Live Server for better experience

### 🔥 New Interactive Features

The enhanced SafeVault now includes **real working security implementations**:

- **Live Input Validation**: Test actual XSS and SQL injection attacks
- **Password Security Demo**: See secure hashing and strength analysis in action  
- **Rate Limiting**: Watch enterprise-grade DDoS protection work
- **CSRF Protection**: Understand token-based security
- **Timing Attack Prevention**: Learn about constant-time operations

### 📊 Sample Security Tests

The interactive demo includes real attack vectors:
- `<script>alert('XSS')</script>` - Script injection
- `'; DROP TABLE users; --` - SQL injection
- `../../../etc/passwd` - Path traversal
- Common password analysis with strength scoring

## 📚 Learning Activities

### Activity 1: Input Validation & SQL Security 🛡️
- **Focus**: XSS Prevention, SQL Injection Protection
- **Files**: `Activities/Activity1_SecureAudit/`
- **Interactive Demo**: Web form security testing
- **Skills**: Input sanitization, parameterized queries, secure database design

### Activity 2: Authentication & Authorization 🔑
- **Focus**: Password Security, Session Management, Access Control
- **Files**: `Activities/Activity2_Authentication/`
- **Tools**: Password strength checker, hash generators
- **Skills**: Secure authentication, role-based access control, session security

### Activity 3: Advanced Security Features 🚀
- **Focus**: Rate Limiting, CSRF Protection, Security Headers
- **Files**: `Activities/Activity3_AdvancedSecurity/`
- **Advanced Topics**: Timing attacks, threat detection, API security
- **Skills**: Advanced security patterns, threat mitigation, security architecture

## 🌐 Interactive Web Interface

The SafeVault web interface provides:
- **Real-time Security Testing**: Test XSS and SQL injection inputs
- **Password Strength Analysis**: Interactive password security checker  
- **Security Headers Review**: Analysis of security configurations
- **Educational Feedback**: Learn from both successes and failures

### Key Features:
- Input validation testing forms
- SQL injection demonstration environment
- XSS prevention examples with live feedback
- Password security analysis tools
- Security headers evaluation

## 🏗️ Project Structure

```
SafeVault/
├── Program.cs              # Main console application entry point
├── WebUI/                  # Interactive web interface
│   ├── index.html         # Main web application
│   ├── styles.css         # Professional styling
│   └── script.js          # Security testing logic
├── Activities/             # Educational content
│   ├── Activity1_SecureAudit/
│   ├── Activity2_Authentication/
│   └── Activity3_AdvancedSecurity/
└── .github/               # Project configuration
    └── copilot-instructions.md
```

## 🔧 Development

### Building the Project
```bash
# Clean build
dotnet clean
dotnet build

# Run with detailed output
dotnet run --verbosity normal
```

### VS Code Tasks
Use `Ctrl+Shift+P` → "Tasks: Run Task" → "Build SafeVault Console"

## 🛡️ Security Features Demonstrated

### Input Validation & Sanitization
- **Real Attack Detection**: Identifies XSS, SQL injection, path traversal, command injection
- **HTML Encoding**: Proper output sanitization to prevent script execution
- **Educational Feedback**: Shows both detected threats and safe alternatives
- **OWASP Compliance**: Follows industry-standard security practices

### Authentication Security
- **Secure Password Hashing**: SHA-256 with cryptographic salts (educational - use bcrypt/Argon2 in production)
- **Salt Generation**: 256-bit cryptographically random salts
- **Password Strength Analysis**: NIST-compliant scoring system
- **Timing Attack Prevention**: Constant-time password comparison
- **Session Token Generation**: Cryptographically secure session management

### Advanced Protection
- **Rate Limiting**: Sliding window algorithm with configurable limits
- **CSRF Token Protection**: HMAC-signed tokens with timestamp validation  
- **Security Headers**: CSP, X-Frame-Options, HSTS implementation guidance
- **Constant-Time Operations**: Prevents timing-based information leakage

### 📚 Educational Implementation Details

Every security class includes:
- **Comprehensive Documentation**: Why each technique is important
- **Real Attack Examples**: Actual malicious payloads used in demonstrations
- **Security Best Practices**: Industry-standard implementations
- **Vulnerability Explanations**: How attacks work and how to prevent them
- **Progressive Learning**: From basic concepts to enterprise-level security

## 📖 Educational Philosophy

SafeVault emphasizes:
- **Learning by Doing**: Interactive exercises and real testing
- **Security by Design**: Best practices from the ground up  
- **Real-World Relevance**: Practical, applicable security scenarios
- **Progressive Complexity**: Building from basics to advanced concepts

## 🤝 Contributing

This is an educational project. Contributions that enhance the learning experience are welcome:
- Additional security scenarios
- Improved educational content
- Enhanced interactive demonstrations
- Better visualization of security concepts

## 📄 License

Educational use - please refer to individual activity guides for specific learning objectives and completion criteria.

## 🎓 Learning Outcomes

After completing SafeVault, learners will be able to:
- Identify and prevent common web vulnerabilities
- Implement secure authentication and authorization
- Apply security best practices in real applications
- Understand advanced security concepts and threat mitigation
- Design security-first applications and systems

---

**Stay secure! 🛡️** - The SafeVault Team
