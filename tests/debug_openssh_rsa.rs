#[test]
fn debug_openssh_rsa_parsing() {
    use base64::Engine;
    use rsa::traits::PublicKeyParts;
    
    let pem_content = include_str!("test_rsa_key");
    
    // Extract base64 content
    let der_encoded: String = pem_content
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    
    let der = base64::engine::general_purpose::STANDARD.decode(&der_encoded).expect("Base64 decode failed");
    
    // Parse manually
    use std::io::Cursor;
    use std::io::Read;
    
    let mut cursor = Cursor::new(&der);
    
    // Skip magic, cipher, kdf, kdf_opts, nkeys, pub_key
    cursor.read_exact(&mut [0u8; 15]).expect("magic");
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf).expect("cipher len");
    let cipher_len = u32::from_be_bytes(buf) as usize;
    cursor.read_exact(&mut vec![0u8; cipher_len]).expect("cipher");
    cursor.read_exact(&mut buf).expect("kdf len");
    let kdf_len = u32::from_be_bytes(buf) as usize;
    cursor.read_exact(&mut vec![0u8; kdf_len]).expect("kdf");
    cursor.read_exact(&mut buf).expect("kdf opts len");
    let kdf_opts_len = u32::from_be_bytes(buf) as usize;
    cursor.read_exact(&mut vec![0u8; kdf_opts_len]).expect("kdf opts");
    cursor.read_exact(&mut buf).expect("nkeys");
    let _nkeys = u32::from_be_bytes(buf) as usize;
    cursor.read_exact(&mut buf).expect("pub key len");
    let pub_key_len = u32::from_be_bytes(buf) as usize;
    cursor.read_exact(&mut vec![0u8; pub_key_len]).expect("pub key");
    
    // Read private key blob
    cursor.read_exact(&mut buf).expect("priv key len");
    let priv_key_len = u32::from_be_bytes(buf) as usize;
    let mut priv_key_blob = vec![0u8; priv_key_len];
    cursor.read_exact(&mut priv_key_blob).expect("priv key blob");
    
    let mut blob_cursor = Cursor::new(&priv_key_blob);
    
    // Read checkint1, checkint2
    let mut checkint1_buf = [0u8; 4];
    blob_cursor.read_exact(&mut checkint1_buf).expect("checkint1");
    let checkint1 = u32::from_be_bytes(checkint1_buf);
    let mut checkint2_buf = [0u8; 4];
    blob_cursor.read_exact(&mut checkint2_buf).expect("checkint2");
    let checkint2 = u32::from_be_bytes(checkint2_buf);
    println!("checkint1: {}, checkint2: {}", checkint1, checkint2);
    
    // Read algorithm string
    let mut algo_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut algo_len_buf).expect("algo len");
    let algo_len = u32::from_be_bytes(algo_len_buf) as usize;
    let mut algo = vec![0u8; algo_len];
    blob_cursor.read_exact(&mut algo).expect("algo");
    let algorithm = String::from_utf8(algo).expect("algo");
    println!("algorithm: {}", algorithm);
    
    // Read RSA components
    let mut n_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut n_len_buf).expect("n len");
    let n_len = u32::from_be_bytes(n_len_buf) as usize;
    let mut n = vec![0u8; n_len];
    blob_cursor.read_exact(&mut n).expect("n");
    println!("n len: {}", n_len);
    
    let mut e_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut e_len_buf).expect("e len");
    let e_len = u32::from_be_bytes(e_len_buf) as usize;
    let mut e = vec![0u8; e_len];
    blob_cursor.read_exact(&mut e).expect("e");
    println!("e len: {}", e_len);
    
    // Read private exponent (d)
    let mut d_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut d_len_buf).expect("d len");
    let d_len = u32::from_be_bytes(d_len_buf) as usize;
    let mut d = vec![0u8; d_len];
    blob_cursor.read_exact(&mut d).expect("d");
    println!("d len: {}", d_len);
    
    // Read coefficient (iqmp) - comes BEFORE p and q in OpenSSH format
    let mut coef_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut coef_len_buf).expect("coef len");
    let coef_len = u32::from_be_bytes(coef_len_buf) as usize;
    let mut coef = vec![0u8; coef_len];
    blob_cursor.read_exact(&mut coef).expect("coef");
    println!("coef len: {}", coef_len);
    
    let mut p_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut p_len_buf).expect("p len");
    let p_len = u32::from_be_bytes(p_len_buf) as usize;
    let mut p = vec![0u8; p_len];
    blob_cursor.read_exact(&mut p).expect("p");
    println!("p len: {}", p_len);
    
    let mut q_len_buf = [0u8; 4];
    blob_cursor.read_exact(&mut q_len_buf).expect("q len");
    let q_len = u32::from_be_bytes(q_len_buf) as usize;
    let mut q = vec![0u8; q_len];
    blob_cursor.read_exact(&mut q).expect("q");
    println!("q len: {}", q_len);
    
    // Debug: show stripping flags
    let n_needs_strip = n.len() > 1 && n[0] == 0x00 && (n[1] & 0x80) != 0;
    let p_needs_strip = p.len() > 1 && p[0] == 0x00 && (p[1] & 0x80) != 0;
    let q_needs_strip = q.len() > 1 && q[0] == 0x00 && (q[1] & 0x80) != 0;
    let coef_needs_strip = coef.len() > 1 && coef[0] == 0x00 && (coef[1] & 0x80) != 0;
    println!("\nn needs strip: {}, p needs strip: {}, q needs strip: {}, coef needs strip: {}", 
             n_needs_strip, p_needs_strip, q_needs_strip, coef_needs_strip);
    
    // Strip leading zeros from mpint encoding
    let n_stripped = if n_needs_strip { &n[1..] } else { &n[..] };
    let p_stripped = if p_needs_strip { &p[1..] } else { &p[..] };
    let q_stripped = if q_needs_strip { &q[1..] } else { &q[..] };
    let coef_stripped = if coef_needs_strip { &coef[1..] } else { &coef[..] };
    
    // Convert to BigUint
    let n_big = rsa::BigUint::from_bytes_be(n_stripped);
    let e_big = rsa::BigUint::from_bytes_be(&e);
    let d_big = rsa::BigUint::from_bytes_be(&d);
    let p_big = rsa::BigUint::from_bytes_be(p_stripped);
    let q_big = rsa::BigUint::from_bytes_be(q_stripped);
    let _coef_big = rsa::BigUint::from_bytes_be(coef_stripped);
    
    println!("\nn bits: {}, e bits: {}, d bits: {}, p bits: {}, q bits: {}", 
             n_big.bits(), e_big.bits(), d_big.bits(), p_big.bits(), q_big.bits());
    
    // Debug: verify n = p * q BEFORE moving values
    let n_check = p_big.clone() * q_big.clone();
    let n_bits_before = n_big.clone().bits();
    let n_eq_check = n_big.clone() == n_check;
    println!("\nn = p * q check: {}", if n_eq_check { "PASS" } else { "FAIL" });
    
    if !n_eq_check {
        println!("Expected n bits: {}, got n_check bits: {}", n_bits_before, n_check.bits());
        let ns_slice = n_stripped.len().min(10);
        let ps_slice = p_stripped.len().min(10);
        let qs_slice = q_stripped.len().min(10);
        println!("n_stripped bytes (first {}): {:02x?}", ns_slice, &n_stripped[..ns_slice]);
        println!("p_stripped bytes (first {}): {:02x?}", ps_slice, &p_stripped[..ps_slice]);
        println!("q_stripped bytes (first {}): {:02x?}", qs_slice, &q_stripped[..qs_slice]);
        let ncs_bytes = n_check.to_bytes_be();
        let ncs_slice = ncs_bytes.len().min(10);
        println!("p_stripped * q_stripped bytes (first {}): {:02x?}", ncs_slice, &ncs_bytes[..ncs_slice]);
    }
    
    // Try to construct
    match rsa::RsaPrivateKey::from_components(
        n_big,
        e_big,
        d_big,
        vec![p_big, q_big],
    ) {
        Ok(key) => {
            println!("✓ RSA key constructed successfully!");
            println!("Key modulus bits: {}", key.n().bits());
        }
        Err(e) => {
            println!("✗ RSA key construction failed: {:?}", e);
        }
    }
}