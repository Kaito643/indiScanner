@echo off
REM Double-click to start the ThreatHarvester web dashboard and open it in the browser.
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep 5; Start-Process 'http://127.0.0.1:8080'"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0th.ps1" serve %*
