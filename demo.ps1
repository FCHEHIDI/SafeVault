# SafeVault Demo Script - Automated Security Testing
# This PowerShell script demonstrates the interactive security features

Write-Host "SafeVault Interactive Security Demo" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This demo will automatically test:" -ForegroundColor Yellow
Write-Host "- XSS Prevention and Input Validation" -ForegroundColor Green
Write-Host "- Password Security and Hashing" -ForegroundColor Green  
Write-Host "- Rate Limiting and CSRF Protection" -ForegroundColor Green
Write-Host "- Timing Attack Prevention" -ForegroundColor Green
Write-Host ""
Write-Host "Starting automated demo in 3 seconds..." -ForegroundColor Yellow

Start-Sleep -Seconds 3

# Run the interactive demo (option 5)
"5" | dotnet run

Write-Host ""
Write-Host "Demo completed! Check the console output above for detailed security analysis." -ForegroundColor Green
Write-Host "Try running dotnet run manually and select option 5 for full interactive experience!" -ForegroundColor Cyan
