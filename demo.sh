#!/bin/bash
# SafeVault Demo Script - Automated Security Testing
# This script demonstrates the interactive security features

echo "🔥 SafeVault Interactive Security Demo"
echo "====================================="
echo ""
echo "This demo will automatically test:"
echo "✓ XSS Prevention & Input Validation"
echo "✓ Password Security & Hashing"
echo "✓ Rate Limiting & CSRF Protection"
echo "✓ Timing Attack Prevention"
echo ""
echo "Starting automated demo in 3 seconds..."
sleep 3

# Run the interactive demo (option 5)
echo "5" | dotnet run

echo ""
echo "🎉 Demo completed! Check the console output above for detailed security analysis."
echo "💡 Try running 'dotnet run' manually and select option 5 for full interactive experience!"
