========================================================================
  TheDrunkBots — PC Auto Tunnel Maker & Cloud Sync Software
========================================================================

HOW TO USE ON WINDOWS / MAC / LINUX:
1. GUI Mode (with Live Status Window):
   - Double-click `home_proxy.bat` (Windows) or run `python3 home_proxy.py`
2. Silent Background Mode (runs invisibly + auto-starts on Windows Boot):
   - Double-click `install_autostart.bat` (or `start_background.vbs`)

FEATURES:
- Automatically creates a local authenticated HTTP/HTTPS proxy on 127.0.0.1:8899
- Automatically opens a Pinggy TCP tunnel AND/OR Reverse WebSocket Tunnel to Backend
- Automatically refreshes Pinggy tunnels every 50 minutes (before 60m free expiry)
- Automatically detects internet drops/reconnections and re-syncs with Admin Panel
- Shows up live in your Web Admin Panel under "Tunnel Devices" where you can toggle
  which device is Active (Primary) vs Standby (Fallback)!
