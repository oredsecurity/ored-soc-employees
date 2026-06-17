@echo off
setlocal

set "BIN=C:\Program Files (x86)\ossec-agent\active-response\bin"
set "SRC=%~dp0ored-win-firewall.exe"

if not exist "%SRC%" (
  echo Missing wrapper binary: %SRC%
  exit /b 1
)

copy /Y "%SRC%" "%BIN%\ored-win-firewall-v3.exe" || exit /b 1
copy /Y "%SRC%" "%BIN%\ored-win-firewall-rollback.exe" || exit /b 1

echo Installed ORED ARGOS Windows active-response v3 wrapper.
exit /b 0
