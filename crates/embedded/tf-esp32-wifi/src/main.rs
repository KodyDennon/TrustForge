//! TrustForge K3 — ESP32 WiFi-uplink packet signer.
//!
//! On boot:
//!
//! 1. The ESP-IDF event loop and NVS are initialised. WiFi is brought
//!    up as STA against the SSID/passphrase compiled in below (replace
//!    via `cargo:rustc-env` or NVS in production).
//! 2. The firmware loads the device's ed25519 seed (here, baked-in;
//!    real deployments fetch from NVS-secure or an external SE).
//! 3. Every 30 s the firmware:
//!       - reads a (mock) sensor reading,
//!       - builds a TrustForge L0 packet,
//!       - signs it with `tf-core-no-std::packet::sign_packet`,
//!       - serialises the packet to canonical JSON,
//!       - HTTP-POSTs the JSON body to the configured TrustForge
//!         daemon URL (`tf-daemon` running the HTTP-over-binary bridge).
//! 4. Logs are emitted via the ESP-IDF logging subsystem; attach
//!    `espflash monitor` to see them.

use std::time::Duration;

use anyhow_workaround::Result; // see module below
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::http::client::{Configuration as HttpConfig, EspHttpConnection};
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use heapless::String as HString;
use log::{error, info};

use tf_core_no_std::packet::{sign_packet, Packet};

// --- Configuration (replace with NVS / build-time env in production) ---

const WIFI_SSID: &str = "TrustForge-Lab";
const WIFI_PSK: &str = "trustforge-demo-psk";

const DAEMON_URL: &str = "http://192.168.1.10:8080/v1/packets";

const SIGNER_URI: &str = "tf:actor:device:example.com/esp32-node-001";
const DEFAULT_DEST: &str = "tf:actor:service:example.com/ingest";

const DEV_SEED: [u8; 32] = *b"TrustForge--K3--ESP32-WiFi-Demo!";

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    info!("TrustForge K3: ESP32 WiFi node starting");

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    // 1) WiFi STA bring-up.
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs))?,
        sysloop,
    )?;
    let auth = if WIFI_PSK.is_empty() {
        AuthMethod::None
    } else {
        AuthMethod::WPA2Personal
    };
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: WIFI_SSID.try_into().map_err(|_| anyhow!("ssid too long"))?,
        password: WIFI_PSK.try_into().map_err(|_| anyhow!("psk too long"))?,
        auth_method: auth,
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.connect()?;
    wifi.wait_netif_up()?;
    info!("WiFi up; starting periodic uplink");

    // 2) Periodic uplink loop.
    let seed = ed25519_compact::Seed::from_slice(&DEV_SEED)
        .map_err(|_| anyhow!("seed parse"))?;

    let mut counter: u32 = 0;
    loop {
        counter = counter.wrapping_add(1);
        let payload = sample_sensor(counter);
        let mut id_buf: HString<48> = HString::new();
        let _ = id_buf.push_str("pkt-esp32-");
        let _ = id_buf.push_str(itoa::Buffer::new().format(counter));
        match sign_packet(
            &payload,
            &seed,
            SIGNER_URI,
            id_buf.as_str(),
            SIGNER_URI,
            DEFAULT_DEST,
            "P3",
            Some("2099-01-01T00:00:00Z"),
        ) {
            Ok(pkt) => {
                let json = packet_to_json(&pkt);
                if let Err(e) = post_packet(&json) {
                    error!("uplink failed: {e:?}");
                } else {
                    info!("uplink ok: {} bytes", json.len());
                }
            }
            Err(e) => error!("sign failed: {:?}", e),
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Mock sensor reading. Real deployments read from an attached
/// peripheral (BME280, SCD30, etc.).
fn sample_sensor(counter: u32) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..4].copy_from_slice(&counter.to_be_bytes());
    buf[4..].copy_from_slice(b"K3-ESP32-DEMO");
    buf
}

/// Render a `Packet` as JSON. We use a hand-rolled stringifier rather
/// than serde to keep the payload size predictable on the wire.
fn packet_to_json(p: &Packet) -> String {
    let sig_hex = hex(p.signature.as_slice());
    let pl_hex = hex(p.payload.as_slice());
    let exp = p.expires_at.as_ref().map(|e| e.as_str()).unwrap_or("");
    format!(
        "{{\"packet_version\":\"{}\",\"packet_id\":\"{}\",\"source\":\"{}\",\"destination\":\"{}\",\"priority\":\"{}\",\"emergency\":{},\"created_at\":\"{}\",\"expires_at\":\"{}\",\"signer\":\"{}\",\"algorithm\":\"{}\",\"payload_hex\":\"{}\",\"signature_hex\":\"{}\"}}",
        p.packet_version.as_str(),
        p.packet_id.as_str(),
        p.source.as_str(),
        p.destination.as_str(),
        p.priority.as_str(),
        p.emergency,
        p.created_at.as_str(),
        exp,
        p.signer.as_str(),
        p.algorithm.as_str(),
        pl_hex,
        sig_hex,
    )
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

/// POST the JSON body to the daemon.
fn post_packet(body: &str) -> Result<()> {
    let mut conn = EspHttpConnection::new(&HttpConfig {
        timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    })?;
    let len_str = body.len().to_string();
    let headers = [
        ("Content-Type", "application/json"),
        ("Content-Length", len_str.as_str()),
        ("User-Agent", "tf-esp32-wifi/0.1"),
    ];
    conn.initiate_request(
        esp_idf_svc::http::Method::Post,
        DAEMON_URL,
        &headers,
    )?;
    embedded_io_write_all(&mut conn, body.as_bytes())?;
    conn.initiate_response()?;
    let status = conn.status();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(anyhow!("HTTP {status}"))
    }
}

fn embedded_io_write_all(
    conn: &mut EspHttpConnection,
    mut data: &[u8],
) -> Result<()> {
    use embedded_svc::io::Write;
    while !data.is_empty() {
        let n = conn.write(data)?;
        data = &data[n..];
    }
    Ok(())
}

// We avoid pulling in the `anyhow` crate from the workspace lockfile
// (which version-pins it differently) by re-exporting just the bits
// the firmware needs as a tiny local module.
mod anyhow_workaround {
    pub use anyhow::{anyhow, Result};
}
use anyhow_workaround::anyhow;

// itoa is a stable, no-alloc integer-to-string formatter.
extern crate itoa;
