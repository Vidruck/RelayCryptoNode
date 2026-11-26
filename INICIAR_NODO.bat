@echo off
REM Arranca el nodo RelayCryptoNode (EQ06).
REM Estandar v2.0 en http://localhost:5006/  -  formato anterior (v1) en el puerto 5000.
REM Requiere .NET 8 SDK.
cd /d "%~dp0"
start "" /min cmd /c "timeout /t 15 /nobreak >nul & start http://localhost:5006/"
dotnet run --project src\RelayCryptoNode.WebHost\RelayCryptoNode.WebHost.csproj -c Release
pause
