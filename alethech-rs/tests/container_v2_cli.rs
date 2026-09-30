use std::path::Path;
use std::process::Command;

#[test]
fn adversarial_container_v2_cli() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let result = Command::new("python3")
        .arg(manifest.join("tests/test_cli_security.py"))
        .current_dir(manifest.parent().unwrap())
        .env("ALETHECH_TEST_BINARY", env!("CARGO_BIN_EXE_alethech-container-v2"))
        .env("PYTHONPATH", manifest.parent().unwrap())
        .output()
        .expect("CLI security tests require Python 3 and the Alethech Python package");
    assert!(result.status.success(), "CLI security tests failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}
