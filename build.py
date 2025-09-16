#!/usr/bin/env python3
"""
Sicherer Builder mit Dependency-Check
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

def check_dependencies():
    """Überprüft alle Abhängigkeiten"""
    dependencies = [
        'customtkinter',
        'M2Crypto',
        'pyaudio',
        'stun'
    ]
    
    missing = []
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep}")
        except ImportError:
            missing.append(dep)
            print(f"❌ {dep}")
    
    return missing

def build_with_pyinstaller():
    """Baut mit PyInstaller"""
    print("🔄 Building with PyInstaller...")
    
    # Erstelle spec file für bessere Kontrolle
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('client_private_key.pem', '.'),
        ('client_public_key.pem', '.'),
        ('client_name.txt', '.'),
    ],
    hiddenimports=[
        'customtkinter',
        'M2Crypto',
        'pyaudio',
        'stun',
        'pystun3',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecureSIPClient',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''
    
    with open('client.spec', 'w') as f:
        f.write(spec_content)
    
    # Build mit spec file
    result = subprocess.run([
        'pyinstaller', 'client.spec'
    ], capture_output=True, text=True)
    
    return result.returncode == 0

def main():
    print("🔍 Checking dependencies...")
    missing = check_dependencies()
    
    if missing:
        print(f"\n❌ Missing dependencies: {missing}")
        print("Install with: pip install " + " ".join(missing))
        return False
    
    print("\n✅ All dependencies found!")
    
    if build_with_pyinstaller():
        print("\n🎉 Build successful!")
        print("📦 Binary: dist/SecureSIPClient")
        print("🚀 Run with: ./dist/SecureSIPClient")
        return True
    else:
        print("\n❌ Build failed")
        return False

if __name__ == '__main__':
    main()
