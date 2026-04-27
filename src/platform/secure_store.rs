pub fn encrypt_password(password: &str) -> anyhow::Result<String> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(password.as_bytes()))
}

pub fn decrypt_password(encrypted: &str) -> anyhow::Result<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encrypted)?;
    Ok(String::from_utf8(bytes)?)
}
