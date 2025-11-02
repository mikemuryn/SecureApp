# PowerShell script to run the master config setup in WSL
Write-Host "Running master Cursor configuration setup in WSL..." -ForegroundColor Green
wsl bash -c "cd /home/mikemuryn/DevelopmentProjects/SecureApp && bash setup_master_cursor_config.sh"
Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
