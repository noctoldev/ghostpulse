# GhostPulse

**GhostPulse** is an experimental Windows malware written in Rust, designed as a stealthy (not really) DLL that exfiltrates data using audio pulses instead of traditional network channels. It captures screenshots and clipboard contents, encrypts them with AES-256-CBC, and transmits them covertly via the system's audio hardware, making it a unique proof-of-concept for bypassing network-based detection.

## Features

### Core Functionality
- **Audio-Based Exfiltration**: Encodes data into high/low audio pulses (32767/-32768 at 44.1 kHz), played through speakers for receiver capture.
- **Data Capture**: Grabs low-res screenshots (320x240) and clipboard text using Windows GDI and clipboard APIs.
- **Encryption**: Secures data with AES-256-CBC before exfiltration.

### Stealth Mechanisms
- **Process Spoofing**: Launches a fake `svchost.exe` instance to blend into system processes.
- **Persistence**: Adds itself to the Windows registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) for startup survival.
- **DLL Format**: Compiles as a `cdylib`, loadable via injection or tools like `rundll32.exe`.

### Technical Highlights
- **Pulse Encoding**: Binary data (base64-encoded ciphertext) mapped to audio amplitudes, avoiding network traffic.
- **Minimal Footprint**: Operates without filesystem modifications beyond persistence, reducing traces.

## Dependencies
- **`openssl`**: AES-256-CBC encryption.
- **`rand`**: Key/IV generation.
- **`winapi`**: Windows API for graphics, clipboard, and process management.
- **`windows-sys`**: Audio playback via `waveOut` functions.
- **`serde_json`**: Data structuring.
- **`base64`**: Encoding ciphertext.
- ---
note: this has not been tested, fairly sure it works but needs recieving script which can be made in python. 1 detection on vt as of feb24th.
compiled with cargo build --release --target x86_64-pc-windows-gnu
