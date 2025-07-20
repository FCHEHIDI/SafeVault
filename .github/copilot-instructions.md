<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# SafeVault Security Learning Platform - Copilot Instructions

## Project Context
SafeVault is a cybersecurity education platform focused on teaching secure coding practices through hands-on activities. The project emphasizes practical security implementations and real-world attack/defense scenarios.

## Code Generation Guidelines

### Security-First Approach
- Always implement input validation and sanitization
- Use parameterized queries to prevent SQL injection
- Implement proper error handling without information leakage
- Apply secure authentication and authorization patterns
- Include security headers and CSRF protection where applicable

### Educational Focus
- Code should be educational and well-commented
- Include explanations of security vulnerabilities and mitigations
- Demonstrate both vulnerable and secure implementations for comparison
- Focus on practical, real-world security scenarios

### Technology Stack
- Primary: .NET/C# console application
- Web Interface: HTML, CSS, JavaScript
- Database: Focus on secure database access patterns
- Security Libraries: Use established security frameworks where appropriate

### Code Structure Preferences
- Clear separation between activities/modules
- Consistent naming conventions for security-related functions
- Include completion guides and educational documentation
- Implement progressive difficulty levels across activities

### Security Topics to Emphasize
1. **Input Validation**: XSS prevention, SQL injection protection, data sanitization
2. **Authentication**: Password hashing, secure session management, multi-factor authentication
3. **Authorization**: Role-based access control, permission systems, privilege escalation prevention
4. **Advanced Security**: Rate limiting, CSRF tokens, security headers, timing attack prevention

### Documentation Standards
- Include security rationale for implementation choices
- Provide examples of common vulnerabilities and their fixes
- Document threat models and attack vectors
- Include references to security standards (OWASP, etc.)

When generating code for SafeVault, prioritize security best practices, educational value, and practical applicability to real-world scenarios.
