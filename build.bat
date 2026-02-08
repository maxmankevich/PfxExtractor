@echo off
chcp 65001 >nul

pip install pyinstaller cryptography

if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "*.spec" del "*.spec"

python -m PyInstaller --onefile --windowed --name "PFX Extractor" pfx-extractor.py

if exist "build" rmdir /s /q "build"
if exist "*.spec" del "*.spec"

echo Done! Check "dist" folder.
pause

