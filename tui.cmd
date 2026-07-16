@echo off
REM Double-click to launch the ThreatHarvester terminal UI.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0th.ps1" tui %*
