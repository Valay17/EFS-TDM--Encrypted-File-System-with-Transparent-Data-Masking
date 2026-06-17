@echo off
:: Build EFS client binary for Windows using Nuitka
:: Run this from the project root: scripts\build_client_win.bat

set "ROOT=%~dp0.."
cd /d "%ROOT%\client_pkg"

call "%ROOT%\venv\Scripts\activate.bat"

:: client\client.py is the single entry point; file I/O helpers are inlined (no file_handler.py)
echo [*] Starting Nuitka build...
echo Yes | python -m nuitka ^
    --standalone ^
    --zig ^
    --output-filename=EFS_bin.exe ^
    --output-dir="%ROOT%\compiled_binary" ^
    --include-package=cryptography ^
    --include-package=bcrypt ^
    --include-package=client ^
    --include-package=pyreadline3 ^
    --nofollow-import-to=pytest ^
    --nofollow-import-to=numpy ^
    --nofollow-import-to=PIL ^
    --nofollow-import-to=pandas ^
    --nofollow-import-to=flask ^
    client\client.py

if errorlevel 1 (
    echo [FAIL] Nuitka build failed.
    exit /b 1
)

echo [*] Copying output to portable_client_win\libs\...
if exist "%ROOT%\portable_client_win\libs\" rd /s /q "%ROOT%\portable_client_win\libs"
mkdir "%ROOT%\portable_client_win\libs"
xcopy /e /q "%ROOT%\compiled_binary\client.dist\*" "%ROOT%\portable_client_win\libs\"

echo [ok] Build complete. portable_client_win\ is ready.
