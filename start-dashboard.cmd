@echo off
setlocal
python -B "%~dp0plugins\vps-ops\skills\vps-ops\scripts\dashboard.py" --open
if errorlevel 1 pause
