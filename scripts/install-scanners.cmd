@echo off
REM Run from Git Bash / WSL: bash scripts/install-scanners.sh
REM Or with Docker Desktop + Git Bash:
where bash >nul 2>&1 && bash "%~dp0install-scanners.sh" %* && goto :eof
echo Run this from Git Bash: bash scripts/install-scanners.sh
exit /b 1
