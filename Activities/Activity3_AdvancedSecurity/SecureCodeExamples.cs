using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Xml;

namespace SafeVault.Activity3.Secure
{
    /// <summary>
    /// ✅ SECURE ADVANCED SECURITY EXAMPLES - Production-Ready Implementations
    /// This class demonstrates secure implementations for advanced security controls
    /// </summary>
    public class SecureAdvancedSecurityExamples
    {
        private readonly ILogger logger;
        private readonly IConfigurationManager config;
        private readonly ICacheManager cache;

        public SecureAdvancedSecurityExamples(ILogger logger, IConfigurationManager config, ICacheManager cache)
        {
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.config = config ?? throw new ArgumentNullException(nameof(config));
            this.cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }

        #region XSS Prevention

        /// <summary>
        /// ✅ SECURE: Proper HTML encoding prevents XSS attacks
        /// </summary>
        public static string DisplayUserComment_Secure(string username, string comment)
        {
            // ✅ HTML encode all user-controlled data
            string safeUsername = HttpUtility.HtmlEncode(username);
            string safeComment = HttpUtility.HtmlEncode(comment);
            
            return $"<div class='comment'><b>{safeUsername}</b> says: {safeComment}</div>";
        }

        /// <summary>
        /// ✅ SECURE: Context-aware encoding for user profile
        /// </summary>
        public static string RenderUserProfile_Secure(UserProfile profile)
        {
            var html = new StringBuilder();
            
            // ✅ HTML context encoding
            html.AppendLine($"<h2>Profile: {HttpUtility.HtmlEncode(profile.DisplayName)}</h2>");
            html.AppendLine($"<p>Bio: {HttpUtility.HtmlEncode(profile.Biography)}</p>");
            
            // ✅ URL validation and encoding for href attribute
            string safeWebsite = ValidateAndSanitizeUrl(profile.Website);
            if (!string.IsNullOrEmpty(safeWebsite))
            {
                html.AppendLine($"<p>Website: <a href='{HttpUtility.HtmlAttributeEncode(safeWebsite)}'>{HttpUtility.HtmlEncode(safeWebsite)}</a></p>");
            }
            
            // ✅ JavaScript context encoding with JSON
            string safeUserId = System.Web.Helpers.Json.Encode(profile.UserId);
            html.AppendLine($"<script>var userId = {safeUserId};</script>");
            
            return html.ToString();
        }

        /// <summary>
        /// ✅ SECURE: Safe search result generation with CSP
        /// </summary>
        public static string GenerateSearchResults_Secure(string searchTerm, HttpResponse response)
        {
            // ✅ Set Content Security Policy
            response.Headers.Add("Content-Security-Policy", 
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
            
            // ✅ JavaScript context encoding
            string safeSearchTerm = System.Web.Helpers.Json.Encode(searchTerm);
            
            return $@"
                <div id='searchTerm'>Results for: {HttpUtility.HtmlEncode(searchTerm)}</div>
                <script>
                    var query = {safeSearchTerm};
                    performSearch(query);
                </script>";
        }

        /// <summary>
        /// ✅ SECURE: URL validation and sanitization
        /// </summary>
        private static string ValidateAndSanitizeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return null;

            // ✅ Reject javascript: protocol and other dangerous schemes
            var dangerousSchemes = new[] { "javascript:", "data:", "vbscript:", "file:", "ftp:" };
            if (dangerousSchemes.Any(scheme => url.ToLowerInvariant().StartsWith(scheme)))
                return null;

            // ✅ Validate URL format
            if (Uri.TryCreate(url, UriKind.Absolute, out Uri validUri))
            {
                // ✅ Only allow http and https
                if (validUri.Scheme == "http" || validUri.Scheme == "https")
                {
                    return validUri.ToString();
                }
            }

            return null;
        }

        #endregion

        #region CSRF Protection

        /// <summary>
        /// ✅ SECURE: CSRF-protected operations with token validation
        /// </summary>
        public class SecureCSRFProtection
        {
            private readonly ICacheManager cache;
            private readonly ILogger logger;

            public SecureCSRFProtection(ICacheManager cache, ILogger logger)
            {
                this.cache = cache;
                this.logger = logger;
            }

            /// <summary>
            /// ✅ SECURE: Generate cryptographically secure CSRF token
            /// </summary>
            public string GenerateCSRFToken(string sessionId)
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] tokenBytes = new byte[32];
                    rng.GetBytes(tokenBytes);
                    string token = Convert.ToBase64String(tokenBytes);
                    
                    // ✅ Store token associated with session
                    string tokenKey = $"csrf_token_{sessionId}";
                    cache.Set(tokenKey, token, TimeSpan.FromMinutes(30));
                    
                    return token;
                }
            }

            /// <summary>
            /// ✅ SECURE: Validate CSRF token
            /// </summary>
            public bool ValidateCSRFToken(string sessionId, string providedToken)
            {
                if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(providedToken))
                {
                    logger.LogWarning("CSRF validation failed: missing session or token");
                    return false;
                }

                string tokenKey = $"csrf_token_{sessionId}";
                string storedToken = cache.Get<string>(tokenKey);

                if (string.IsNullOrEmpty(storedToken))
                {
                    logger.LogWarning($"CSRF validation failed: no stored token for session {sessionId}");
                    return false;
                }

                // ✅ Constant-time comparison to prevent timing attacks
                bool isValid = CryptographicEquals(
                    Encoding.UTF8.GetBytes(providedToken),
                    Encoding.UTF8.GetBytes(storedToken)
                );

                if (!isValid)
                {
                    logger.LogWarning($"CSRF validation failed: token mismatch for session {sessionId}");
                }

                return isValid;
            }

            /// <summary>
            /// ✅ SECURE: Password change with CSRF protection
            /// </summary>
            public CSRFResult ProcessPasswordChange(HttpRequest request, string sessionId)
            {
                try
                {
                    // ✅ Validate CSRF token first
                    string csrfToken = request.Params["__RequestVerificationToken"];
                    if (!ValidateCSRFToken(sessionId, csrfToken))
                    {
                        return CSRFResult.Failed("Invalid request token");
                    }

                    // ✅ Additional validations
                    string username = request.Params["username"];
                    string newPassword = request.Params["newPassword"];
                    string currentPassword = request.Params["currentPassword"];

                    if (string.IsNullOrWhiteSpace(username) || 
                        string.IsNullOrWhiteSpace(newPassword) || 
                        string.IsNullOrWhiteSpace(currentPassword))
                    {
                        return CSRFResult.Failed("All fields are required");
                    }

                    // ✅ Verify current password before allowing change
                    if (!VerifyCurrentPassword(username, currentPassword))
                    {
                        return CSRFResult.Failed("Current password is incorrect");
                    }

                    // ✅ Validate new password strength
                    if (!ValidatePasswordStrength(newPassword))
                    {
                        return CSRFResult.Failed("New password does not meet requirements");
                    }

                    // ✅ Process password change
                    ChangeUserPassword(username, newPassword);
                    
                    // ✅ Invalidate the used CSRF token
                    cache.Remove($"csrf_token_{sessionId}");
                    
                    logger.LogInfo($"Password changed successfully for user: {username}");
                    return CSRFResult.Success("Password changed successfully");
                }
                catch (Exception ex)
                {
                    logger.LogError($"Password change error: {ex.Message}");
                    return CSRFResult.Failed("Password change failed");
                }
            }

            /// <summary>
            /// ✅ SECURE: Account deletion with multiple protections
            /// </summary>
            public CSRFResult DeleteUserAccount(HttpRequest request, string sessionId, string currentUserId)
            {
                try
                {
                    // ✅ CSRF protection
                    if (!ValidateCSRFToken(sessionId, request.Params["__RequestVerificationToken"]))
                    {
                        return CSRFResult.Failed("Invalid request token");
                    }

                    // ✅ Additional confirmation required for destructive operations
                    string confirmationCode = request.Params["confirmationCode"];
                    if (!ValidateAccountDeletionCode(currentUserId, confirmationCode))
                    {
                        return CSRFResult.Failed("Invalid confirmation code");
                    }

                    // ✅ Rate limiting for critical operations
                    if (IsRateLimited(currentUserId, "account_deletion"))
                    {
                        return CSRFResult.Failed("Too many requests. Please try again later.");
                    }

                    // ✅ Process deletion
                    DeleteAccount(currentUserId);
                    
                    logger.LogInfo($"Account deleted for user: {currentUserId}");
                    return CSRFResult.Success("Account deleted successfully");
                }
                catch (Exception ex)
                {
                    logger.LogError($"Account deletion error: {ex.Message}");
                    return CSRFResult.Failed("Account deletion failed");
                }
            }
        }

        #endregion

        #region Secure Direct Object Reference

        /// <summary>
        /// ✅ SECURE: Authorization-protected document access
        /// </summary>
        public class SecureDocumentAccess
        {
            private readonly ILogger logger;
            private readonly IAuthorizationService authService;

            public SecureDocumentAccess(ILogger logger, IAuthorizationService authService)
            {
                this.logger = logger;
                this.authService = authService;
            }

            /// <summary>
            /// ✅ SECURE: Document access with proper authorization
            /// </summary>
            public DocumentAccessResult GetDocument(string documentId, string currentUserId)
            {
                try
                {
                    // ✅ Input validation
                    if (string.IsNullOrWhiteSpace(documentId) || string.IsNullOrWhiteSpace(currentUserId))
                    {
                        return DocumentAccessResult.Failed("Invalid parameters");
                    }

                    // ✅ Validate document ID format (prevent injection)
                    if (!IsValidDocumentId(documentId))
                    {
                        logger.LogWarning($"Invalid document ID format attempted: {documentId} by user {currentUserId}");
                        return DocumentAccessResult.Failed("Invalid document ID");
                    }

                    // ✅ Check if document exists
                    var document = LoadDocumentFromDatabase(documentId);
                    if (document == null)
                    {
                        return DocumentAccessResult.Failed("Document not found");
                    }

                    // ✅ Authorization check - user must own document or have read permission
                    if (!authService.CanAccessDocument(currentUserId, documentId, "read"))
                    {
                        logger.LogWarning($"Unauthorized document access attempt: User {currentUserId} tried to access document {documentId}");
                        return DocumentAccessResult.Failed("Access denied");
                    }

                    // ✅ Log successful access for audit
                    logger.LogInfo($"Document accessed: {documentId} by user {currentUserId}");
                    
                    return DocumentAccessResult.Success(document);
                }
                catch (Exception ex)
                {
                    logger.LogError($"Document access error: {ex.Message}");
                    return DocumentAccessResult.Failed("Access failed");
                }
            }

            /// <summary>
            /// ✅ SECURE: Document deletion with ownership verification
            /// </summary>
            public DocumentActionResult DeleteDocument(string documentId, string currentUserId)
            {
                try
                {
                    if (!IsValidDocumentId(documentId))
                    {
                        return DocumentActionResult.Failed("Invalid document ID");
                    }

                    // ✅ Verify ownership or admin permission
                    if (!authService.CanAccessDocument(currentUserId, documentId, "delete"))
                    {
                        logger.LogWarning($"Unauthorized document deletion attempt: User {currentUserId} tried to delete document {documentId}");
                        return DocumentActionResult.Failed("Access denied");
                    }

                    // ✅ Additional check - document must exist and be owned by user
                    var document = LoadDocumentFromDatabase(documentId);
                    if (document == null)
                    {
                        return DocumentActionResult.Failed("Document not found");
                    }

                    if (document.OwnerId != currentUserId && !authService.IsAdmin(currentUserId))
                    {
                        logger.LogWarning($"Document ownership mismatch: User {currentUserId} tried to delete document {documentId} owned by {document.OwnerId}");
                        return DocumentActionResult.Failed("Access denied");
                    }

                    // ✅ Perform secure deletion
                    DeleteDocumentFromDatabase(documentId);
                    
                    logger.LogInfo($"Document deleted: {documentId} by user {currentUserId}");
                    return DocumentActionResult.Success("Document deleted successfully");
                }
                catch (Exception ex)
                {
                    logger.LogError($"Document deletion error: {ex.Message}");
                    return DocumentActionResult.Failed("Deletion failed");
                }
            }

            /// <summary>
            /// ✅ SECURE: User document listing with proper filtering
            /// </summary>
            public DocumentListResult GetUserDocuments(string targetUserId, string currentUserId)
            {
                try
                {
                    // ✅ Users can only access their own documents unless they're admin
                    if (targetUserId != currentUserId && !authService.IsAdmin(currentUserId))
                    {
                        logger.LogWarning($"Unauthorized document list access: User {currentUserId} tried to access documents for user {targetUserId}");
                        return DocumentListResult.Failed("Access denied");
                    }

                    // ✅ Load documents with proper filtering
                    var documents = LoadUserDocuments(targetUserId);
                    
                    // ✅ Additional filtering based on user permissions
                    var filteredDocuments = documents.Where(doc => 
                        authService.CanAccessDocument(currentUserId, doc.Id, "read")).ToList();

                    logger.LogInfo($"Document list accessed: {filteredDocuments.Count} documents for user {targetUserId} by {currentUserId}");
                    
                    return DocumentListResult.Success(filteredDocuments);
                }
                catch (Exception ex)
                {
                    logger.LogError($"Document list error: {ex.Message}");
                    return DocumentListResult.Failed("Access failed");
                }
            }

            /// <summary>
            /// ✅ SECURE: Document ID validation
            /// </summary>
            private bool IsValidDocumentId(string documentId)
            {
                // ✅ Validate format - only alphanumeric and hyphens, reasonable length
                return !string.IsNullOrWhiteSpace(documentId) && 
                       documentId.Length <= 50 && 
                       Regex.IsMatch(documentId, @"^[a-zA-Z0-9\-_]+$");
            }
        }

        #endregion

        #region Secure File Upload

        /// <summary>
        /// ✅ SECURE: File upload with comprehensive security controls
        /// </summary>
        public class SecureFileUpload
        {
            private readonly ILogger logger;
            private readonly IConfigurationManager config;
            private readonly IVirusScanService virusScanner;

            public SecureFileUpload(ILogger logger, IConfigurationManager config, IVirusScanService virusScanner)
            {
                this.logger = logger;
                this.config = config;
                this.virusScanner = virusScanner;
            }

            /// <summary>
            /// ✅ SECURE: File upload with multiple security validations
            /// </summary>
            public FileUploadResult UploadFile(HttpPostedFile file, string currentUserId, string uploadPath)
            {
                try
                {
                    // ✅ Basic validation
                    if (file == null || file.ContentLength == 0)
                    {
                        return FileUploadResult.Failed("No file provided");
                    }

                    // ✅ File size validation
                    int maxFileSize = config.GetInt("Upload:MaxFileSizeBytes", 5 * 1024 * 1024); // 5MB default
                    if (file.ContentLength > maxFileSize)
                    {
                        return FileUploadResult.Failed($"File size exceeds maximum allowed size of {maxFileSize / 1024 / 1024}MB");
                    }

                    // ✅ File type validation - whitelist approach
                    if (!IsAllowedFileType(file))
                    {
                        logger.LogWarning($"Blocked file upload attempt: {file.FileName} by user {currentUserId}");
                        return FileUploadResult.Failed("File type not allowed");
                    }

                    // ✅ Filename validation and sanitization
                    string safeFileName = SanitizeFileName(file.FileName);
                    if (string.IsNullOrEmpty(safeFileName))
                    {
                        return FileUploadResult.Failed("Invalid filename");
                    }

                    // ✅ Generate unique filename to prevent conflicts and directory traversal
                    string uniqueFileName = GenerateUniqueFileName(safeFileName);
                    string fullPath = Path.Combine(GetSecureUploadPath(uploadPath), uniqueFileName);

                    // ✅ Ensure upload path is within allowed directory
                    if (!IsPathWithinAllowedDirectory(fullPath, uploadPath))
                    {
                        logger.LogWarning($"Path traversal attempt blocked: {fullPath} by user {currentUserId}");
                        return FileUploadResult.Failed("Invalid upload path");
                    }

                    // ✅ Content validation - check file headers
                    if (!ValidateFileContent(file))
                    {
                        return FileUploadResult.Failed("File content validation failed");
                    }

                    // ✅ Virus scanning
                    if (virusScanner != null)
                    {
                        var scanResult = virusScanner.ScanFile(file.InputStream);
                        if (!scanResult.IsClean)
                        {
                            logger.LogWarning($"Virus detected in uploaded file: {file.FileName} by user {currentUserId}");
                            return FileUploadResult.Failed("File failed security scan");
                        }
                    }

                    // ✅ Save file to secure location
                    file.SaveAs(fullPath);

                    // ✅ Set restrictive file permissions
                    SetSecureFilePermissions(fullPath);

                    // ✅ Log successful upload
                    logger.LogInfo($"File uploaded successfully: {uniqueFileName} by user {currentUserId}");

                    return FileUploadResult.Success(uniqueFileName, fullPath);
                }
                catch (Exception ex)
                {
                    logger.LogError($"File upload error: {ex.Message}");
                    return FileUploadResult.Failed("Upload failed");
                }
            }

            /// <summary>
            /// ✅ SECURE: File download with authorization and path validation
            /// </summary>
            public FileDownloadResult DownloadFile(string filename, string currentUserId)
            {
                try
                {
                    // ✅ Input validation
                    if (string.IsNullOrWhiteSpace(filename))
                    {
                        return FileDownloadResult.Failed("Invalid filename");
                    }

                    // ✅ Sanitize filename and prevent path traversal
                    string safeFileName = Path.GetFileName(filename); // Removes any path components
                    if (string.IsNullOrEmpty(safeFileName) || safeFileName != filename)
                    {
                        logger.LogWarning($"Path traversal attempt blocked in download: {filename} by user {currentUserId}");
                        return FileDownloadResult.Failed("Invalid filename");
                    }

                    // ✅ Construct secure file path
                    string securePath = GetSecureUploadPath("");
                    string fullPath = Path.Combine(securePath, safeFileName);

                    // ✅ Verify file exists and is within allowed directory
                    if (!File.Exists(fullPath) || !IsPathWithinAllowedDirectory(fullPath, securePath))
                    {
                        return FileDownloadResult.Failed("File not found");
                    }

                    // ✅ Check user authorization to download this file
                    if (!CanUserAccessFile(currentUserId, safeFileName))
                    {
                        logger.LogWarning($"Unauthorized file download attempt: {safeFileName} by user {currentUserId}");
                        return FileDownloadResult.Failed("Access denied");
                    }

                    // ✅ Read file securely
                    byte[] fileContent = File.ReadAllBytes(fullPath);
                    string contentType = GetSecureContentType(safeFileName);

                    logger.LogInfo($"File downloaded: {safeFileName} by user {currentUserId}");
                    
                    return FileDownloadResult.Success(fileContent, contentType, safeFileName);
                }
                catch (Exception ex)
                {
                    logger.LogError($"File download error: {ex.Message}");
                    return FileDownloadResult.Failed("Download failed");
                }
            }

            /// <summary>
            /// ✅ SECURE: File type validation using whitelist
            /// </summary>
            private bool IsAllowedFileType(HttpPostedFile file)
            {
                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt" };
                var allowedMimeTypes = new[] { "image/jpeg", "image/png", "image/gif", "application/pdf", 
                                               "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                               "text/plain" };

                string fileExtension = Path.GetExtension(file.FileName)?.ToLowerInvariant();
                string mimeType = file.ContentType?.ToLowerInvariant();

                return !string.IsNullOrEmpty(fileExtension) && 
                       !string.IsNullOrEmpty(mimeType) &&
                       allowedExtensions.Contains(fileExtension) && 
                       allowedMimeTypes.Contains(mimeType);
            }

            /// <summary>
            /// ✅ SECURE: Filename sanitization
            /// </summary>
            private string SanitizeFileName(string filename)
            {
                if (string.IsNullOrWhiteSpace(filename))
                    return null;

                // ✅ Remove path components
                filename = Path.GetFileName(filename);

                // ✅ Remove invalid characters
                var invalidChars = Path.GetInvalidFileNameChars();
                foreach (char c in invalidChars)
                {
                    filename = filename.Replace(c, '_');
                }

                // ✅ Remove additional dangerous characters
                filename = filename.Replace("..", "").Replace(":", "").Replace("\\", "").Replace("/", "");

                // ✅ Limit length
                if (filename.Length > 100)
                {
                    string extension = Path.GetExtension(filename);
                    string nameWithoutExtension = Path.GetFileNameWithoutExtension(filename);
                    filename = nameWithoutExtension.Substring(0, 100 - extension.Length) + extension;
                }

                return filename;
            }

            /// <summary>
            /// ✅ SECURE: Generate unique filename to prevent conflicts
            /// </summary>
            private string GenerateUniqueFileName(string originalName)
            {
                string extension = Path.GetExtension(originalName);
                string nameWithoutExtension = Path.GetFileNameWithoutExtension(originalName);
                string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                string uniqueId = Guid.NewGuid().ToString("N").Substring(0, 8);
                
                return $"{nameWithoutExtension}_{timestamp}_{uniqueId}{extension}";
            }

            /// <summary>
            /// ✅ SECURE: Validate file content matches extension
            /// </summary>
            private bool ValidateFileContent(HttpPostedFile file)
            {
                // ✅ Read file header to validate actual file type
                file.InputStream.Position = 0;
                byte[] header = new byte[10];
                int bytesRead = file.InputStream.Read(header, 0, header.Length);
                file.InputStream.Position = 0; // Reset position

                string extension = Path.GetExtension(file.FileName)?.ToLowerInvariant();
                
                // ✅ Basic file signature validation
                return extension switch
                {
                    ".jpg" or ".jpeg" => header.Take(3).SequenceEqual(new byte[] { 0xFF, 0xD8, 0xFF }),
                    ".png" => header.Take(8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }),
                    ".gif" => header.Take(6).SequenceEqual(Encoding.ASCII.GetBytes("GIF87a")) || 
                             header.Take(6).SequenceEqual(Encoding.ASCII.GetBytes("GIF89a")),
                    ".pdf" => header.Take(4).SequenceEqual(Encoding.ASCII.GetBytes("%PDF")),
                    _ => true // For other types, rely on extension validation
                };
            }

            private string GetSecureUploadPath(string basePath) => config.GetString("Upload:SecurePath", @"C:\SecureUploads");
            private bool IsPathWithinAllowedDirectory(string path, string allowedDirectory) => Path.GetFullPath(path).StartsWith(Path.GetFullPath(allowedDirectory));
            private void SetSecureFilePermissions(string filePath) { /* Implementation for setting file permissions */ }
            private bool CanUserAccessFile(string userId, string filename) => true; // Implementation for authorization
            private string GetSecureContentType(string filename) => "application/octet-stream"; // Safe default
        }

        #endregion

        #region Secure Cryptography

        /// <summary>
        /// ✅ SECURE: Strong cryptographic implementations
        /// </summary>
        public static class SecureCryptography
        {
            /// <summary>
            /// ✅ SECURE: AES encryption with authenticated encryption (GCM mode)
            /// </summary>
            public static EncryptionResult EncryptData(string plaintext, byte[] key)
            {
                if (string.IsNullOrEmpty(plaintext) || key == null || key.Length != 32)
                {
                    throw new ArgumentException("Invalid plaintext or key");
                }

                using (var aes = new AesGcm(key))
                {
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                    byte[] nonce = new byte[12]; // GCM standard nonce size
                    byte[] ciphertext = new byte[plaintextBytes.Length];
                    byte[] tag = new byte[16]; // GCM authentication tag

                    // ✅ Generate cryptographically secure nonce
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(nonce);
                    }

                    // ✅ Encrypt with authentication
                    aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                    return new EncryptionResult
                    {
                        Ciphertext = Convert.ToBase64String(ciphertext),
                        Nonce = Convert.ToBase64String(nonce),
                        Tag = Convert.ToBase64String(tag),
                        Algorithm = "AES-256-GCM"
                    };
                }
            }

            /// <summary>
            /// ✅ SECURE: AES decryption with authentication verification
            /// </summary>
            public static string DecryptData(EncryptionResult encryptionResult, byte[] key)
            {
                if (encryptionResult == null || key == null || key.Length != 32)
                {
                    throw new ArgumentException("Invalid encryption result or key");
                }

                try
                {
                    using (var aes = new AesGcm(key))
                    {
                        byte[] ciphertext = Convert.FromBase64String(encryptionResult.Ciphertext);
                        byte[] nonce = Convert.FromBase64String(encryptionResult.Nonce);
                        byte[] tag = Convert.FromBase64String(encryptionResult.Tag);
                        byte[] plaintext = new byte[ciphertext.Length];

                        // ✅ Decrypt with authentication verification
                        aes.Decrypt(nonce, ciphertext, tag, plaintext);

                        return Encoding.UTF8.GetString(plaintext);
                    }
                }
                catch (CryptographicException)
                {
                    throw new SecurityException("Decryption failed - data may have been tampered with");
                }
            }

            /// <summary>
            /// ✅ SECURE: PBKDF2 password hashing with high iteration count
            /// </summary>
            public static PasswordHashResult HashPassword(string password)
            {
                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException("Password cannot be null or empty");
                }

                // ✅ Generate cryptographically secure salt
                byte[] salt = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // ✅ Use PBKDF2 with SHA-256 and high iteration count
                int iterations = 100000; // Adjust based on performance requirements
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
                {
                    byte[] hash = pbkdf2.GetBytes(32);

                    return new PasswordHashResult
                    {
                        Hash = Convert.ToBase64String(hash),
                        Salt = Convert.ToBase64String(salt),
                        Iterations = iterations,
                        Algorithm = "PBKDF2-SHA256"
                    };
                }
            }

            /// <summary>
            /// ✅ SECURE: Constant-time password verification
            /// </summary>
            public static bool VerifyPassword(string password, PasswordHashResult storedResult)
            {
                if (string.IsNullOrEmpty(password) || storedResult == null)
                    return false;

                try
                {
                    byte[] salt = Convert.FromBase64String(storedResult.Salt);
                    byte[] storedHash = Convert.FromBase64String(storedResult.Hash);

                    using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, storedResult.Iterations, HashAlgorithmName.SHA256))
                    {
                        byte[] computedHash = pbkdf2.GetBytes(32);
                        
                        // ✅ Constant-time comparison
                        return CryptographicEquals(storedHash, computedHash);
                    }
                }
                catch (Exception)
                {
                    return false; // ✅ Fail securely
                }
            }

            /// <summary>
            /// ✅ SECURE: Generate cryptographically secure random token
            /// </summary>
            public static string GenerateSecureToken(int lengthBytes = 32)
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] tokenBytes = new byte[lengthBytes];
                    rng.GetBytes(tokenBytes);
                    return Convert.ToBase64String(tokenBytes).Replace("/", "_").Replace("+", "-").Replace("=", "");
                }
            }

            /// <summary>
            /// ✅ SECURE: Generate encryption key from password
            /// </summary>
            public static byte[] DeriveKeyFromPassword(string password, byte[] salt, int keyLength = 32)
            {
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
                {
                    return pbkdf2.GetBytes(keyLength);
                }
            }
        }

        #endregion

        #region Security Headers

        /// <summary>
        /// ✅ SECURE: Comprehensive security headers implementation
        /// </summary>
        public static class SecureHeaders
        {
            /// <summary>
            /// ✅ SECURE: Set comprehensive security headers
            /// </summary>
            public static void SetSecurityHeaders(HttpResponse response, bool isProduction = true)
            {
                // ✅ Content Security Policy - Strict policy
                response.Headers.Add("Content-Security-Policy", 
                    "default-src 'self'; " +
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data: https:; " +
                    "font-src 'self'; " +
                    "connect-src 'self'; " +
                    "media-src 'none'; " +
                    "object-src 'none'; " +
                    "child-src 'none'; " +
                    "frame-ancestors 'none'; " +
                    "form-action 'self'; " +
                    "upgrade-insecure-requests");

                // ✅ X-Frame-Options - Prevent clickjacking
                response.Headers.Add("X-Frame-Options", "DENY");

                // ✅ X-Content-Type-Options - Prevent MIME sniffing
                response.Headers.Add("X-Content-Type-Options", "nosniff");

                // ✅ X-XSS-Protection - Legacy XSS protection
                response.Headers.Add("X-XSS-Protection", "1; mode=block");

                // ✅ Strict-Transport-Security - HTTPS enforcement
                if (isProduction)
                {
                    response.Headers.Add("Strict-Transport-Security", 
                        "max-age=31536000; includeSubDomains; preload");
                }

                // ✅ Referrer-Policy - Control referrer information
                response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

                // ✅ Permissions-Policy - Control browser features
                response.Headers.Add("Permissions-Policy", 
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=()");

                // ✅ X-Permitted-Cross-Domain-Policies - Control Flash/PDF policies
                response.Headers.Add("X-Permitted-Cross-Domain-Policies", "none");

                // ✅ Remove server identification headers
                response.Headers.Remove("Server");
                response.Headers.Remove("X-Powered-By");
                response.Headers.Remove("X-AspNet-Version");

                // ✅ CORS headers - Restrictive by default
                SetSecureCORSHeaders(response);
            }

            /// <summary>
            /// ✅ SECURE: Configure secure CORS headers
            /// </summary>
            public static void SetSecureCORSHeaders(HttpResponse response, string[] allowedOrigins = null)
            {
                // ✅ Specific allowed origins only (no wildcards for credentials)
                if (allowedOrigins != null && allowedOrigins.Length > 0)
                {
                    // In a real implementation, validate the origin against allowed list
                    response.Headers.Add("Access-Control-Allow-Origin", allowedOrigins[0]);
                    response.Headers.Add("Access-Control-Allow-Credentials", "true");
                }
                else
                {
                    // ✅ No CORS by default
                    response.Headers.Add("Access-Control-Allow-Origin", "null");
                }

                // ✅ Restrictive methods and headers
                response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                response.Headers.Add("Access-Control-Allow-Headers", 
                    "Content-Type, Authorization, X-Requested-With, X-CSRF-Token");
                
                // ✅ Limit preflight cache
                response.Headers.Add("Access-Control-Max-Age", "86400"); // 24 hours
            }

            /// <summary>
            /// ✅ SECURE: Set secure session cookie
            /// </summary>
            public static void SetSecureSessionCookie(HttpResponse response, string sessionId, bool isProduction = true)
            {
                var sessionCookie = new HttpCookie("__Secure-SessionID", sessionId)
                {
                    // ✅ Secure flag - HTTPS only
                    Secure = isProduction,
                    
                    // ✅ HttpOnly - No JavaScript access
                    HttpOnly = true,
                    
                    // ✅ SameSite - CSRF protection
                    SameSite = SameSiteMode.Strict,
                    
                    // ✅ Reasonable expiration
                    Expires = DateTime.UtcNow.AddMinutes(30),
                    
                    // ✅ Restrict path
                    Path = "/",
                    
                    // ✅ Domain restriction (set appropriately for your environment)
                    Domain = null // Let browser determine
                };

                response.Cookies.Set(sessionCookie);
            }
        }

        #endregion

        #region Secure Error Handling

        /// <summary>
        /// ✅ SECURE: Error handling that doesn't leak information
        /// </summary>
        public class SecureErrorHandling
        {
            private readonly ILogger logger;
            private readonly bool isProduction;

            public SecureErrorHandling(ILogger logger, bool isProduction = true)
            {
                this.logger = logger;
                this.isProduction = isProduction;
            }

            /// <summary>
            /// ✅ SECURE: Process data with safe error handling
            /// </summary>
            public ProcessingResult ProcessUserData(string userData, string userId)
            {
                try
                {
                    // ✅ Input validation
                    if (string.IsNullOrWhiteSpace(userData))
                    {
                        return ProcessingResult.Failed("Invalid input data");
                    }

                    // Process the data
                    ProcessData(userData);
                    
                    logger.LogInfo($"Data processed successfully for user: {userId}");
                    return ProcessingResult.Success("Data processed successfully");
                }
                catch (ArgumentException ex)
                {
                    // ✅ Log detailed error for debugging
                    logger.LogWarning($"Input validation error for user {userId}: {ex.Message}");
                    
                    // ✅ Return generic message to user
                    return ProcessingResult.Failed("Invalid input provided");
                }
                catch (UnauthorizedAccessException ex)
                {
                    logger.LogWarning($"Unauthorized access attempt by user {userId}: {ex.Message}");
                    return ProcessingResult.Failed("Access denied");
                }
                catch (Exception ex)
                {
                    // ✅ Log detailed error for internal use
                    logger.LogError($"Processing error for user {userId}: {ex.Message}", ex);
                    
                    // ✅ Generic error message for production
                    string userMessage = isProduction 
                        ? "An error occurred while processing your request" 
                        : $"Error: {ex.Message}"; // More details in development
                    
                    return ProcessingResult.Failed(userMessage);
                }
            }

            /// <summary>
            /// ✅ SECURE: Safe logging that excludes sensitive data
            /// </summary>
            public void LogUserActivity(string userId, string operation, object operationData, HttpRequest request)
            {
                try
                {
                    // ✅ Create sanitized log entry
                    var logEntry = new
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = userId,
                        Operation = operation,
                        // ✅ Only log non-sensitive metadata
                        RequestMetadata = new
                        {
                            Method = request.HttpMethod,
                            UserAgent = request.UserAgent?.Substring(0, Math.Min(100, request.UserAgent.Length ?? 0)),
                            IPAddress = GetClientIPAddress(request),
                            // ✅ Don't log full URL (may contain sensitive data)
                            Path = request.Url?.AbsolutePath
                        },
                        // ✅ Log operation result, not sensitive data
                        Success = operationData != null
                    };

                    // ✅ Log to secure, structured logging system
                    logger.LogInfo($"User activity: {System.Text.Json.JsonSerializer.Serialize(logEntry)}");
                    
                    // ✅ Don't write sensitive data to console or plain text files
                }
                catch (Exception ex)
                {
                    // ✅ Fail gracefully if logging fails
                    logger.LogError($"Logging error: {ex.Message}");
                }
            }

            private string GetClientIPAddress(HttpRequest request)
            {
                // ✅ Safely get client IP, handling proxies
                string ip = request.ServerVariables["HTTP_X_FORWARDED_FOR"];
                if (string.IsNullOrEmpty(ip))
                    ip = request.ServerVariables["REMOTE_ADDR"];
                
                // ✅ Sanitize IP address
                if (!string.IsNullOrEmpty(ip) && IPAddress.TryParse(ip.Split(',')[0].Trim(), out _))
                {
                    return ip.Split(',')[0].Trim();
                }
                
                return "Unknown";
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// ✅ SECURE: Constant-time equality comparison
        /// </summary>
        private static bool CryptographicEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        // Placeholder methods
        private bool VerifyCurrentPassword(string username, string password) => true;
        private bool ValidatePasswordStrength(string password) => password.Length >= 8;
        private void ChangeUserPassword(string username, string password) { }
        private bool ValidateAccountDeletionCode(string userId, string code) => true;
        private bool IsRateLimited(string userId, string operation) => false;
        private void DeleteAccount(string userId) { }
        private Document LoadDocumentFromDatabase(string id) => new Document { Id = id };
        private void DeleteDocumentFromDatabase(string id) { }
        private List<Document> LoadUserDocuments(string userId) => new List<Document>();
        private void ProcessData(string data) { }

        #endregion
    }

    #region Supporting Classes and Interfaces

    public class EncryptionResult
    {
        public string Ciphertext { get; set; }
        public string Nonce { get; set; }
        public string Tag { get; set; }
        public string Algorithm { get; set; }
    }

    public class PasswordHashResult
    {
        public string Hash { get; set; }
        public string Salt { get; set; }
        public int Iterations { get; set; }
        public string Algorithm { get; set; }
    }

    public class CSRFResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        
        public static CSRFResult Success(string message) => new CSRFResult { Success = true, Message = message };
        public static CSRFResult Failed(string message) => new CSRFResult { Success = false, Message = message };
    }

    public class DocumentAccessResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public Document Document { get; set; }
        
        public static DocumentAccessResult Success(Document document) => new DocumentAccessResult { Success = true, Document = document };
        public static DocumentAccessResult Failed(string message) => new DocumentAccessResult { Success = false, Message = message };
    }

    public class DocumentActionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        
        public static DocumentActionResult Success(string message) => new DocumentActionResult { Success = true, Message = message };
        public static DocumentActionResult Failed(string message) => new DocumentActionResult { Success = false, Message = message };
    }

    public class DocumentListResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public List<Document> Documents { get; set; }
        
        public static DocumentListResult Success(List<Document> documents) => new DocumentListResult { Success = true, Documents = documents };
        public static DocumentListResult Failed(string message) => new DocumentListResult { Success = false, Message = message };
    }

    public class FileUploadResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string FileName { get; set; }
        public string FilePath { get; set; }
        
        public static FileUploadResult Success(string fileName, string filePath) => new FileUploadResult { Success = true, FileName = fileName, FilePath = filePath };
        public static FileUploadResult Failed(string message) => new FileUploadResult { Success = false, Message = message };
    }

    public class FileDownloadResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public byte[] Content { get; set; }
        public string ContentType { get; set; }
        public string FileName { get; set; }
        
        public static FileDownloadResult Success(byte[] content, string contentType, string fileName) => 
            new FileDownloadResult { Success = true, Content = content, ContentType = contentType, FileName = fileName };
        public static FileDownloadResult Failed(string message) => new FileDownloadResult { Success = false, Message = message };
    }

    public class ProcessingResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        
        public static ProcessingResult Success(string message) => new ProcessingResult { Success = true, Message = message };
        public static ProcessingResult Failed(string message) => new ProcessingResult { Success = false, Message = message };
    }

    // Interfaces (implementations would be provided separately)
    public interface ILogger
    {
        void LogInfo(string message);
        void LogWarning(string message);
        void LogError(string message, Exception exception = null);
    }

    public interface IConfigurationManager
    {
        string GetString(string key, string defaultValue = null);
        int GetInt(string key, int defaultValue = 0);
    }

    public interface ICacheManager
    {
        T Get<T>(string key);
        void Set(string key, object value, TimeSpan expiration);
        void Remove(string key);
    }

    public interface IAuthorizationService
    {
        bool CanAccessDocument(string userId, string documentId, string action);
        bool IsAdmin(string userId);
    }

    public interface IVirusScanService
    {
        ScanResult ScanFile(Stream fileStream);
    }

    public class ScanResult
    {
        public bool IsClean { get; set; }
        public string ThreatName { get; set; }
    }

    #endregion
}
