@echo off
cd /d "%~dp0"
echo Installing TheDrunkBots PC Tunnel into Windows Startup (Auto-Run on Boot)...
python -c "import home_proxy; ok, msg = home_proxy.install_windows_autostart(); print(msg)"
echo Starting tunnel in background...
wscript.exe "%~dp0start_background.vbs"
echo Done! TheDrunkBots Tunnel is now running in the background and will auto-start on boot.
pause
