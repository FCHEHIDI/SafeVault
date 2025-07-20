// SafeVault Security Learning Platform - Interactive Security Testing
document.addEventListener('DOMContentLoaded', function() {
    
    // XSS Testing
    document.getElementById('xssTestForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const input = document.getElementById('userInput').value;
        const result = document.getElementById('xssResult');
        
        testXSSProtection(input, result);
    });
    
    // SQL Injection Testing
    document.getElementById('sqlTestForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const input = document.getElementById('sqlInput').value;
        const result = document.getElementById('sqlResult');
        
        testSQLProtection(input, result);
    });
    
    // Password Strength Testing
    document.getElementById('passwordTestForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const input = document.getElementById('passwordInput').value;
        const result = document.getElementById('passwordResult');
        
        testPasswordStrength(input, result);
    });
});

function testXSSProtection(input, resultElement) {
    resultElement.className = 'result';
    
    // Check for common XSS patterns
    const xssPatterns = [
        /<script.*?>.*?<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe.*?>/gi,
        /<object.*?>/gi,
        /<embed.*?>/gi
    ];
    
    let threats = [];
    
    xssPatterns.forEach(pattern => {
        if (pattern.test(input)) {
            threats.push('Potential XSS vector detected');
        }
    });
    
    if (threats.length > 0) {
        resultElement.className += ' danger';
        resultElement.innerHTML = `
            <strong>⚠️ Security Risk Detected!</strong><br>
            Input contains potential XSS vectors.<br>
            <em>In a real application, this input would be sanitized or rejected.</em><br>
            <strong>Recommended:</strong> HTML encode: ${htmlEncode(input)}
        `;
    } else {
        resultElement.className += ' safe';
        resultElement.innerHTML = `
            <strong>✅ Input appears safe</strong><br>
            No obvious XSS patterns detected.<br>
            <em>Processed safely: ${htmlEncode(input)}</em>
        `;
    }
}

function testSQLProtection(input, resultElement) {
    resultElement.className = 'result';
    
    // Check for SQL injection patterns
    const sqlPatterns = [
        /('|\\')|(;)|(\-\-)|(\|)|(\*|%)/gi,
        /(union|select|insert|update|delete|drop|create|alter|exec|execute)/gi,
        /(\bor\b|\band\b)/gi,
        /1\s*=\s*1/gi
    ];
    
    let threats = [];
    
    sqlPatterns.forEach(pattern => {
        if (pattern.test(input)) {
            threats.push('SQL injection pattern detected');
        }
    });
    
    if (threats.length > 0) {
        resultElement.className += ' danger';
        resultElement.innerHTML = `
            <strong>🚨 SQL Injection Risk!</strong><br>
            Input contains suspicious SQL patterns.<br>
            <em>In secure code: Use parameterized queries</em><br>
            <strong>Example:</strong> SELECT * FROM users WHERE id = @userId
        `;
    } else {
        resultElement.className += ' safe';
        resultElement.innerHTML = `
            <strong>✅ SQL Input Analysis Complete</strong><br>
            No obvious injection patterns detected.<br>
            <em>Always use parameterized queries in production!</em>
        `;
    }
}

function testPasswordStrength(password, resultElement) {
    resultElement.className = 'result';
    
    let score = 0;
    let feedback = [];
    
    // Length check
    if (password.length >= 8) score++;
    else feedback.push('Use at least 8 characters');
    
    if (password.length >= 12) score++;
    
    // Character variety
    if (/[a-z]/.test(password)) score++;
    else feedback.push('Include lowercase letters');
    
    if (/[A-Z]/.test(password)) score++;
    else feedback.push('Include uppercase letters');
    
    if (/[0-9]/.test(password)) score++;
    else feedback.push('Include numbers');
    
    if (/[^A-Za-z0-9]/.test(password)) score++;
    else feedback.push('Include special characters');
    
    // Common patterns check
    if (/(.)\1{2,}/.test(password)) {
        score--;
        feedback.push('Avoid repeating characters');
    }
    
    const commonPasswords = ['password', '123456', 'qwerty', 'admin'];
    if (commonPasswords.some(common => password.toLowerCase().includes(common))) {
        score--;
        feedback.push('Avoid common password patterns');
    }
    
    // Display results
    if (score >= 5) {
        resultElement.className += ' safe';
        resultElement.innerHTML = `
            <strong>🔒 Strong Password!</strong><br>
            Score: ${score}/6<br>
            <em>This password meets security requirements.</em>
        `;
    } else if (score >= 3) {
        resultElement.className += ' warning';
        resultElement.innerHTML = `
            <strong>⚠️ Moderate Password</strong><br>
            Score: ${score}/6<br>
            <strong>Improvements:</strong> ${feedback.join(', ')}
        `;
    } else {
        resultElement.className += ' danger';
        resultElement.innerHTML = `
            <strong>❌ Weak Password</strong><br>
            Score: ${score}/6<br>
            <strong>Critical improvements needed:</strong> ${feedback.join(', ')}
        `;
    }
}

function checkSecurityHeaders() {
    const result = document.getElementById('headersResult');
    result.className = 'result info';
    
    // Comprehensive security headers with importance levels
    const criticalHeaders = [
        {
            name: 'Content-Security-Policy',
            description: 'Prevents XSS attacks by controlling resource loading',
            example: "default-src 'self'; script-src 'self'",
            importance: 'CRITICAL'
        },
        {
            name: 'Strict-Transport-Security',
            description: 'Enforces HTTPS and prevents downgrade attacks', 
            example: 'max-age=31536000; includeSubDomains',
            importance: 'CRITICAL'
        }
    ];
    
    const highHeaders = [
        {
            name: 'X-Frame-Options',
            description: 'Prevents clickjacking by controlling iframe embedding',
            example: 'DENY or SAMEORIGIN',
            importance: 'HIGH'
        },
        {
            name: 'X-Content-Type-Options',
            description: 'Prevents MIME type sniffing attacks',
            example: 'nosniff',
            importance: 'HIGH'
        }
    ];
    
    const mediumHeaders = [
        {
            name: 'Referrer-Policy',
            description: 'Controls referrer information in requests',
            example: 'strict-origin-when-cross-origin',
            importance: 'MEDIUM'
        },
        {
            name: 'Permissions-Policy',
            description: 'Controls browser features and APIs',
            example: 'camera=(), microphone=(), geolocation=()',
            importance: 'MEDIUM'
        }
    ];
    
    // Try to check actual headers (limited in browser environment)
    let actualHeadersInfo = '';
    try {
        // Note: Most security headers cannot be read via JavaScript due to security restrictions
        actualHeadersInfo = `
            <div style="background: #fffacd; padding: 10px; margin: 10px 0; border-left: 4px solid #ffa500;">
                <strong>⚠️ Browser Security Note:</strong><br>
                Most security headers cannot be read via JavaScript for security reasons.
                Use browser dev tools (Network tab) or tools like <em>securityheaders.com</em> to check actual headers.
            </div>
        `;
    } catch (e) {
        actualHeadersInfo = '<em>Headers cannot be accessed via JavaScript</em>';
    }
    
    result.innerHTML = `
        <strong>�️ Security Headers Analysis</strong><br><br>
        
        ${actualHeadersInfo}
        
        <div style="margin-bottom: 20px;">
            <strong>🚨 CRITICAL PRIORITY:</strong>
            <ul style="margin-left: 20px; margin-top: 5px;">
                ${criticalHeaders.map(h => `
                    <li style="margin-bottom: 8px;">
                        <strong>${h.name}:</strong> ${h.description}<br>
                        <code style="background: #f0f0f0; padding: 2px 4px; font-size: 12px;">${h.example}</code>
                    </li>
                `).join('')}
            </ul>
        </div>
        
        <div style="margin-bottom: 20px;">
            <strong>⚠️ HIGH PRIORITY:</strong>
            <ul style="margin-left: 20px; margin-top: 5px;">
                ${highHeaders.map(h => `
                    <li style="margin-bottom: 8px;">
                        <strong>${h.name}:</strong> ${h.description}<br>
                        <code style="background: #f0f0f0; padding: 2px 4px; font-size: 12px;">${h.example}</code>
                    </li>
                `).join('')}
            </ul>
        </div>
        
        <div style="margin-bottom: 20px;">
            <strong>💡 MEDIUM PRIORITY:</strong>
            <ul style="margin-left: 20px; margin-top: 5px;">
                ${mediumHeaders.map(h => `
                    <li style="margin-bottom: 8px;">
                        <strong>${h.name}:</strong> ${h.description}<br>
                        <code style="background: #f0f0f0; padding: 2px 4px; font-size: 12px;">${h.example}</code>
                    </li>
                `).join('')}
            </ul>
        </div>
        
        <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin-top: 15px;">
            <strong>🎯 How to Test Your Headers:</strong><br>
            1. <strong>Browser Dev Tools:</strong> Network tab → Select any request → Response Headers<br>
            2. <strong>Online Tools:</strong> securityheaders.com, observatory.mozilla.org<br>
            3. <strong>curl Command:</strong> <code style="background: #f0f0f0; padding: 2px 4px;">curl -I https://yoursite.com</code><br>
            4. <strong>SafeVault Console:</strong> Run option 5 for comprehensive security testing
        </div>
        
        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 10px;">
            <strong>⚡ Quick Security Check:</strong><br>
            Missing security headers can lead to:
            • <strong>XSS attacks</strong> (without CSP)<br>
            • <strong>Clickjacking</strong> (without X-Frame-Options)<br>
            • <strong>MITM attacks</strong> (without HSTS)<br>
            • <strong>Content sniffing</strong> (without X-Content-Type-Options)
        </div>
    `;
}

function togglePassword() {
    const passwordInput = document.getElementById('passwordInput');
    passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
}

function htmlEncode(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
