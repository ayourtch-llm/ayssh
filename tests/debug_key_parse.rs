#[test]
fn debug_key_parse() {
    let pem_content = include_str!("test_rsa_key");
    
    println!("=== PEM Content ===");
    println!("{}", pem_content);
    println!("==================");
    println!();
    
    // Check if it contains OPENSSH marker
    if pem_content.contains("BEGIN OPENSSH PRIVATE KEY") {
        println!("✓ Contains 'BEGIN OPENSSH PRIVATE KEY' marker");
    } else {
        println!("✗ Missing 'BEGIN OPENSSH PRIVATE KEY' marker");
    }
    
    // Extract base64 content
    let der_encoded: String = pem_content
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    
    println!();
    println!("=== Base64 content length: {} ===", der_encoded.len());
    println!("Base64 starts with: {}", &der_encoded[..20]);
    
    // Try to decode
    match base64::decode(&der_encoded) {
        Ok(der) => {
            println!();
            println!("=== DER decoded successfully ===");
            println!("DER length: {} bytes", der.len());
            println!("DER starts with: {:02x?}", &der[..20]);
            
            // Check magic
            if der.len() >= 15 {
                let magic = &der[..15];
                println!("Magic bytes: {:02x?}", magic);
                if magic == b"openssh-key-v1\0" {
                    println!("✓ Valid OpenSSH magic");
                } else {
                    println!("✗ Invalid OpenSSH magic");
                }
            }
        }
        Err(e) => {
            println!();
            println!("✗ Base64 decode error: {:?}", e);
        }
    }
    
    // Try parsing with pem crate
    println!();
    println!("=== Trying pem crate ===");
    match pem::parse(pem_content) {
        Ok(pem) => {
            println!("✓ PEM parsed successfully");
            println!("Tag: {}", pem.tag());
            println!("Contents length: {} bytes", pem.contents().len());
        }
        Err(e) => {
            println!("✗ PEM parse error: {:?}", e);
        }
    }
}