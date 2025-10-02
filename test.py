#!/usr/bin/env python3
import pyaudio
import subprocess
import sys

def run_arecord_test():
    """Testet Audio mit arecord direkt (wie in deinem Beweis)"""
    print("=== ARECORD DIRECT TEST (BEWEIS) ===")
    
    tests = [
        ("S32_LE @ 192kHz Stereo", "-f S32_LE -r 192000 -c 2 -D hw:1,0"),
        ("S24_LE @ 192kHz Stereo", "-f S24_LE -r 192000 -c 2 -D hw:1,0"), 
        ("S16_LE @ 192kHz Stereo", "-f S16_LE -r 192000 -c 2 -D hw:1,0"),
        ("S32_LE @ 96kHz Stereo", "-f S32_LE -r 96000 -c 2 -D hw:1,0"),
        ("S32_LE @ 48kHz Stereo", "-f S32_LE -r 48000 -c 2 -D hw:1,0"),
        ("S32_LE @ 192kHz Mono", "-f S32_LE -r 192000 -c 1 -D hw:1,0"),
    ]
    
    for name, params in tests:
        cmd = f"arecord {params} -d 1 /dev/null 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {name}: OK")
        else:
            print(f"❌ {name}: FAILED")
            # Zeige Fehlerdetails
            if "Cannot allocate memory" in result.stderr:
                print(f"   💥 Memory allocation error")
            if "Invalid argument" in result.stderr:
                print(f"   💥 Invalid argument")
            print(f"   📝 Error: {result.stderr.strip()}")

def check_pyaudio_devices():
    """Detaillierte PyAudio Device-Analyse"""
    print("\n=== PYAUDIO DEVICE DETAIL ANALYSIS ===")
    
    p = pyaudio.PyAudio()
    
    try:
        # Spezifische SA9227 Devices analysieren
        sa9227_devices = []
        for i in range(p.get_device_count()):
            info = p.get_device_info_by_index(i)
            if 'SA9227' in info['name']:
                sa9227_devices.append((i, info))
        
        print(f"🎯 SA9227 USB Audio Devices found: {len(sa9227_devices)}")
        
        for device_id, info in sa9227_devices:
            print(f"\n--- SA9227 Device {device_id} ---")
            print(f"Name: {info['name']}")
            print(f"Hardware: {info.get('hostApi', 'N/A')}")
            print(f"Max Input Channels: {info['maxInputChannels']}")
            print(f"Max Output Channels: {info['maxOutputChannels']}")
            print(f"Default Sample Rate: {info['defaultSampleRate']}")
            
            # Teste verschiedene Konfigurationen für dieses Device
            test_configs = [
                (1, pyaudio.paInt32, 192000, "32-bit Mono @ 192kHz"),
                (2, pyaudio.paInt32, 192000, "32-bit Stereo @ 192kHz"),
                (1, pyaudio.paInt24, 192000, "24-bit Mono @ 192kHz"),
                (2, pyaudio.paInt24, 192000, "24-bit Stereo @ 192kHz"),
                (1, pyaudio.paInt16, 48000, "16-bit Mono @ 48kHz"),
                (2, pyaudio.paInt16, 48000, "16-bit Stereo @ 48kHz"),
            ]
            
            for channels, format, rate, description in test_configs:
                try:
                    # Input Test
                    if info['maxInputChannels'] >= channels:
                        input_supported = p.is_format_supported(
                            rate,
                            input_device=device_id,
                            input_channels=channels,
                            input_format=format
                        )
                        print(f"  🎤 Input {description}: {'✅' if input_supported else '❌'}")
                    else:
                        print(f"  🎤 Input {description}: ❌ (not enough channels)")
                        
                    # Output Test  
                    if info['maxOutputChannels'] >= channels:
                        output_supported = p.is_format_supported(
                            rate,
                            output_device=device_id,
                            output_channels=channels, 
                            output_format=format
                        )
                        print(f"  🔊 Output {description}: {'✅' if output_supported else '❌'}")
                    else:
                        print(f"  🔊 Output {description}: ❌ (not enough channels)")
                        
                except Exception as e:
                    print(f"  💥 {description}: ERROR - {str(e)}")
                    
    finally:
        p.terminate()

def test_pyaudio_streams():
    """Testet tatsächliche PyAudio Stream-Eröffnung"""
    print("\n=== PYAUDIO STREAM PRACTICAL TEST ===")
    
    p = pyaudio.PyAudio()
    
    # SA9227 Device IDs aus deiner Ausgabe
    sa9227_input_id = 4  # hw:1,0 - Input & Output
    sa9227_output_id = 5  # hw:1,1 - Nur Output
    
    test_cases = [
        # (input_device, output_device, channels, format, rate, description)
        (sa9227_input_id, sa9227_output_id, 1, pyaudio.paInt16, 48000, "16-bit Mono @ 48kHz"),
        (sa9227_input_id, sa9227_output_id, 2, pyaudio.paInt16, 48000, "16-bit Stereo @ 48kHz"),
        (sa9227_input_id, sa9227_output_id, 1, pyaudio.paInt24, 48000, "24-bit Mono @ 48kHz"),
        (sa9227_input_id, sa9227_output_id, 2, pyaudio.paInt24, 48000, "24-bit Stereo @ 48kHz"),
        (sa9227_input_id, sa9227_output_id, 1, pyaudio.paInt32, 48000, "32-bit Mono @ 48kHz"),
        (sa9227_input_id, sa9227_output_id, 2, pyaudio.paInt32, 48000, "32-bit Stereo @ 48kHz"),
        (sa9227_input_id, sa9227_output_id, 1, pyaudio.paInt32, 96000, "32-bit Mono @ 96kHz"),
        (sa9227_input_id, sa9227_output_id, 2, pyaudio.paInt32, 96000, "32-bit Stereo @ 96kHz"),
    ]
    
    for input_dev, output_dev, channels, format, rate, description in test_cases:
        print(f"\n🎯 Testing: {description}")
        print(f"   Input: {input_dev}, Output: {output_dev}")
        
        input_stream = None
        output_stream = None
        
        try:
            # Versuche Input Stream
            try:
                input_stream = p.open(
                    format=format,
                    channels=channels,
                    rate=rate,
                    input=True,
                    input_device_index=input_dev,
                    frames_per_buffer=1024
                )
                print("   🎤 Input: ✅ SUCCESS")
                input_stream.stop_stream()
                input_stream.close()
            except Exception as e:
                print(f"   🎤 Input: ❌ FAILED - {str(e)}")
            
            # Versuche Output Stream
            try:
                output_stream = p.open(
                    format=pyaudio.paInt16,  # Output immer 16-bit für Kompatibilität
                    channels=channels,
                    rate=rate,
                    output=True,
                    output_device_index=output_dev,
                    frames_per_buffer=1024
                )
                print("   🔊 Output: ✅ SUCCESS")
                output_stream.stop_stream()
                output_stream.close()
            except Exception as e:
                print(f"   🔊 Output: ❌ FAILED - {str(e)}")
                
        except Exception as e:
            print(f"   💥 Overall: {str(e)}")
        finally:
            # Cleanup
            if input_stream:
                try:
                    input_stream.close()
                except:
                    pass
            if output_stream:
                try:
                    output_stream.close()
                except:
                    pass
    
    p.terminate()

def check_alsa_config():
    """Überprüft ALSA-Konfiguration"""
    print("\n=== ALSA CONFIGURATION CHECK ===")
    
    # Überprüfe ALSA Device-Liste
    print("🔍 ALSA Devices:")
    result = subprocess.run("aplay -l", shell=True, capture_output=True, text=True)
    print(result.stdout)
    
    if result.stderr:
        print("ALSA Errors:")
        print(result.stderr)

def main():
    print("🎵 COMPREHENSIVE SA9227 AUDIO ANALYSIS")
    print("=" * 50)
    
    # 1. Zuerst der Beweis-Test mit arecord
    run_arecord_test()
    
    # 2. Detaillierte PyAudio Analyse
    check_pyaudio_devices()
    
    # 3. Praktische Stream-Tests
    test_pyaudio_streams()
    
    # 4. ALSA Konfiguration
    check_alsa_config()
    
    print("\n" + "=" * 50)
    print("✅ Test completed - Check results above")

if __name__ == "__main__":
    main()
