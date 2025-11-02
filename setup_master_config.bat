@echo off
REM Windows batch file to run setup_master_cursor_config.sh in WSL
wsl bash -c "cd /home/mikemuryn/DevelopmentProjects/SecureApp && chmod +x setup_master_cursor_config.sh && ./setup_master_cursor_config.sh"
pause
