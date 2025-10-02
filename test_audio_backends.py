#!/usr/bin/env python3
import sys
import subprocess

def test_pyaudio():
    """Testet PyAudio"""
    try:
        import pyaudio
        p = pyaudio.PyAudio()
        print("✅ PyAudio verfügbar")
        print(f"   Geräte: {p.get_device_count()}")
        p.terminate()
        return True
    except Exception as e:
        print(f"❌ PyAudio nicht verfügbar: {e}")
        return False

def test_pysndfile():
    """Testet PySndfile"""
    try:
        import sndfile
        print("✅ PySndfile verfügbar")
        return True
    except Exception as e:
        print(f"❌ PySndfile nicht verfügbar: {e}")
        return False

def test_sox():
    """Testet SoX"""
    try:
        result = subprocess.run(["which", "sox"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ SoX verfügbar")
            return True
        else:
            print("❌ SoX nicht verfügbar")
            return False
    except Exception as e:
        print(f"❌ SoX Test fehlgeschlagen: {e}")
        return False

def test_sndfile_play():
    """Testet sndfile-play"""
    try:
        result = subprocess.run(["which", "sndfile-play"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ sndfile-play verfügbar")
            return True
        else:
            print("❌ sndfile-play nicht verfügbar")
            return False
    except Exception as e:
        print(f"❌ sndfile-play Test fehlgeschlagen: {e}")
        return False

if __name__ == "__main__":
    print("🔊 Testing Audio Backends auf OpenBSD...")
    
    backends = {
        "PyAudio": test_pyaudio,
        "PySndfile": test_pysndfile, 
        "SoX": test_sox,
        "sndfile-play": test_sndfile_play
    }
    
    available = []
    for name, test_func in backends.items():
        if test_func():
            available.append(name)
    
    print(f"\n🎯 Verfügbare Backends: {available}")
    
    if available:
        print("✅ Mindestens ein Audio-Backend verfügbar")
    else:
        print("❌ Keine Audio-Backends verfügbar")
