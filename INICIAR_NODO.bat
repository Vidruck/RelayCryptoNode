@echo off
REM Arranca el nodo RelayCryptoNode (NODO06) en el puerto 5000.
REM Requiere .NET 8 SDK. El panel queda en http://localhost:5000/
cd /d "%~dp0"
dotnet run --project src\RelayCryptoNode.WebHost\RelayCryptoNode.WebHost.csproj -c Release
pause
