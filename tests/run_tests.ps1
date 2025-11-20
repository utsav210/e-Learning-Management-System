# PowerShell script to run security tests with virtual environment
# Usage: .\tests\run_tests.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Security Tests Execution Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$venvPath = Join-Path (Split-Path -Parent $projectRoot) "myenv\Scripts\Activate.ps1"

Write-Host "Project Root: $projectRoot" -ForegroundColor Yellow
Write-Host "Virtual Environment: $venvPath" -ForegroundColor Yellow
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path $venvPath)) {
    Write-Host "ERROR: Virtual environment not found at: $venvPath" -ForegroundColor Red
    Write-Host "Please ensure the virtual environment is set up correctly." -ForegroundColor Red
    exit 1
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Green
& $venvPath

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to activate virtual environment" -ForegroundColor Red
    exit 1
}

# Change to project root
Set-Location $projectRoot

Write-Host ""
Write-Host "Running security tests..." -ForegroundColor Green
Write-Host ""

# Run tests using Django's test runner
python manage.py test tests --verbosity=2

$testExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($testExitCode -eq 0) {
    Write-Host "All tests completed successfully!" -ForegroundColor Green
} else {
    Write-Host "Some tests failed. Check output above." -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan

exit $testExitCode

