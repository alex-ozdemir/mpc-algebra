use std::fs::write;

use conec::{coord::CoordError, Coord, CoordConfig};
use rcgen::generate_simple_self_signed;

#[tokio::main]
async fn run(coord_cfg: CoordConfig) -> Result<(), CoordError> {
    let coord = { Coord::new(coord_cfg).await.unwrap() };

    coord.await
}

fn main() {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut cert_path = std::env::temp_dir();
    cert_path.push("cert.der");
    let mut key_path = std::env::temp_dir();
    key_path.push("key.der");

    let cert_bytes = cert.serialize_der().expect("expected der");
    write(&cert_path, &cert_bytes).expect("expected to write to file");
    write(&key_path, &cert.serialize_private_key_der()).expect("expected to write to file");

    let mut coord_cfg = CoordConfig::new_from_file(&cert_path, &key_path).unwrap();
    coord_cfg.enable_stateless_retry();

    run(coord_cfg).unwrap();
}
