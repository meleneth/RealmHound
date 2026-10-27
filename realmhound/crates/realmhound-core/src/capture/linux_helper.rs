//! Narrow Linux capture process protocol. Only this executable needs CAP_NET_RAW.
//! The pipe contains framed packets; it never carries commands or arbitrary filters.

use super::sniffer::MAX_CAPTURE_FRAME;
use super::{
    packet_channel, CaptureError, CaptureHandle, NetworkInterface, PacketFormat, PacketReceiver,
    RawPacket, Sniffer, SnifferConfig, DEFAULT_QUEUE_CAPACITY,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

fn capture_interface_name(override_name: Option<String>) -> String {
    override_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "any".into())
}

/// Entry point for the separately installed, capability-bearing executable.
pub fn run() -> Result<(), String> {
    let name = capture_interface_name(std::env::var("REALMHOUND_CAPTURE_INTERFACE").ok());
    let iface = NetworkInterface {
        name,
        description: None,
        addresses: Vec::new(),
    };
    let mut stdout = std::io::stdout().lock();
    let mut sniffer = match Sniffer::new(&iface, SnifferConfig::default()) {
        Ok(sniffer) => sniffer,
        Err(error) => {
            let message = error.to_string();
            let bytes = message.as_bytes();
            let len = bytes.len().min(u16::MAX as usize);
            stdout.write_all(&[1]).map_err(|e| e.to_string())?;
            stdout
                .write_all(&(len as u16).to_be_bytes())
                .map_err(|e| e.to_string())?;
            stdout.write_all(&bytes[..len]).map_err(|e| e.to_string())?;
            stdout.flush().map_err(|e| e.to_string())?;
            return Err(message);
        }
    };
    stdout.write_all(&[0]).map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    let mut oversized_dropped = 0u64;
    loop {
        match sniffer.next_packet() {
            Ok(Some(packet)) => {
                if packet.data.len() > MAX_CAPTURE_FRAME {
                    oversized_dropped += 1;
                    eprintln!(
                        "oversized capture frames dropped: {oversized_dropped} total (latest was {} bytes; maximum is {MAX_CAPTURE_FRAME})",
                        packet.data.len()
                    );
                    continue;
                }
                let secs = packet.timestamp.timestamp();
                let nanos = packet.timestamp.timestamp_subsec_nanos();
                stdout
                    .write_all(&(packet.data.len() as u32).to_be_bytes())
                    .map_err(|e| e.to_string())?;
                stdout
                    .write_all(&[packet.packet_format.code()])
                    .map_err(|e| e.to_string())?;
                stdout
                    .write_all(&secs.to_be_bytes())
                    .map_err(|e| e.to_string())?;
                stdout
                    .write_all(&nanos.to_be_bytes())
                    .map_err(|e| e.to_string())?;
                stdout.write_all(&packet.data).map_err(|e| e.to_string())?;
            }
            Ok(None) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_packet(input: &mut impl Read) -> std::io::Result<RawPacket> {
    let mut header = [0u8; 17];
    input.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
    if len > MAX_CAPTURE_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "capture frame too large",
        ));
    }
    let format = PacketFormat::from_code(header[4]).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid capture format")
    })?;
    let secs = i64::from_be_bytes(header[5..13].try_into().unwrap());
    let nanos = u32::from_be_bytes(header[13..17].try_into().unwrap());
    let timestamp = chrono::DateTime::from_timestamp(secs, nanos).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid capture timestamp")
    })?;
    let mut data = vec![0; len];
    input.read_exact(&mut data)?;
    Ok(RawPacket {
        timestamp,
        packet_format: format,
        #[cfg(feature = "latency-diagnostics")]
        enqueued_at: None,
        data,
    })
}

/// Spawn the helper beside the GUI and bridge its stdout into the existing queue.
pub fn start() -> Result<
    (
        CaptureHandle,
        PacketReceiver,
        tokio::sync::oneshot::Receiver<String>,
    ),
    CaptureError,
> {
    let exe = std::env::current_exe().map_err(|e| CaptureError::CaptureError(e.to_string()))?;
    let helper = exe.with_file_name("realmhound-capture");
    let mut child = Command::new(&helper).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|e| CaptureError::CaptureError(format!("Cannot launch {}: {e}. Install the Linux capture helper beside RealmHound and run the one-time setup.", helper.display())))?;
    let mut output = child.stdout.take().unwrap();
    let errors = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(errors).lines().map_while(Result::ok) {
            tracing::warn!("Linux capture helper: {line}");
        }
    });
    let mut status = [0];
    output.read_exact(&mut status).map_err(|e| {
        CaptureError::CaptureError(format!("Capture helper exited during startup: {e}"))
    })?;
    if status[0] != 0 {
        let mut len = [0; 2];
        output
            .read_exact(&mut len)
            .map_err(|e| CaptureError::CaptureError(e.to_string()))?;
        let mut message = vec![0; u16::from_be_bytes(len) as usize];
        output
            .read_exact(&mut message)
            .map_err(|e| CaptureError::CaptureError(e.to_string()))?;
        let _ = child.wait();
        return Err(CaptureError::CaptureError(
            String::from_utf8_lossy(&message).into_owned(),
        ));
    }
    let child = Arc::new(Mutex::new(child));
    let handle = CaptureHandle::with_linux_child(child.clone());
    let (tx, rx) = packet_channel(DEFAULT_QUEUE_CAPACITY);
    let (detected_tx, detected_rx) = tokio::sync::oneshot::channel();
    let _ = detected_tx.send(capture_interface_name(
        std::env::var("REALMHOUND_CAPTURE_INTERFACE").ok(),
    ));
    std::thread::spawn(move || {
        while let Ok(packet) = read_packet(&mut output) {
            if tx.send(packet).is_err() {
                break;
            }
        }
        if let Ok(mut child) = child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        tracing::debug!("Linux capture helper stopped");
    });
    Ok((handle, rx, detected_rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_round_trip() {
        let packet = RawPacket {
            timestamp: chrono::Utc::now(),
            packet_format: PacketFormat::LinuxSll2,
            #[cfg(feature = "latency-diagnostics")]
            enqueued_at: None,
            data: vec![1, 2, 3],
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(packet.data.len() as u32).to_be_bytes());
        bytes.push(packet.packet_format.code());
        bytes.extend_from_slice(&packet.timestamp.timestamp().to_be_bytes());
        bytes.extend_from_slice(&packet.timestamp.timestamp_subsec_nanos().to_be_bytes());
        bytes.extend_from_slice(&packet.data);
        let decoded = read_packet(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.data, packet.data);
        assert_eq!(decoded.packet_format, PacketFormat::LinuxSll2);
    }

    #[test]
    fn accepts_frame_larger_than_maximum_ip_packet() {
        let data = vec![0; usize::from(u16::MAX) + 20];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.push(PacketFormat::LinuxSll2.code());
        bytes.extend_from_slice(&0i64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&data);

        let decoded = read_packet(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.data.len(), data.len());
    }

    #[test]
    fn rejects_frame_larger_than_capture_limit() {
        let mut header = [0u8; 17];
        header[..4].copy_from_slice(&((MAX_CAPTURE_FRAME + 1) as u32).to_be_bytes());

        let error = read_packet(&mut header.as_slice()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn defaults_to_any_with_manual_override() {
        assert_eq!(capture_interface_name(None), "any");
        assert_eq!(capture_interface_name(Some("eth0".into())), "eth0");
        assert_eq!(capture_interface_name(Some(" ".into())), "any");
    }
}
