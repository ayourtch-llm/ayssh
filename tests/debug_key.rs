use base64::Engine;

#[test]
fn debug_rsa_key_parse() {
    let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEApKskAVxvB/bN/SeqOmiMmqRHnoRF8TIk768Fp0QF0ky1mjrRcAbB
b4qhm/s5RIdDYOl/AszPy/Q6KoSyMIsjN1hcvxpOJnZdP5IEclQRRGzrfh9krDmU2n0oNp
SsYIzFjyQ2nQtL4yV4z9IVRurajLhWnAQuAhTnPrp2jAL/8mfFP6RFjxTCx8P0QwrkuX8p
WnCFKuU7lMpg+zEydtbnStJ9VJ17lnNkEgPWxwJmwFnhuAJWV+p8MuE5gf3Ovxl7sKff4R
C6BSCfppX1LbXcMTWEU00h5OpzXQ0N4FR2+g08z+mi3ev2MBdlcQIe8IFN75fsKCCCLfEh
bnVK/RPKVwAAA8jAFbyDwBW8gwAAAAdzc2gtcnNhAAABAQCkqyQBXG8H9s39J6o6aIyapE
eehEXxMiTvrwWnRAXSTLWaOtFwBsFviqGb+zlEh0Ng6X8CzM/L9DoqhLIwiyM3WFy/Gk4m
dl0/kgRyVBFEbOt+H2SsOZTafSg2lKxgjMWPJDadC0vjJXjP0hVG6tqMuFacBC4CFOc+un
aMAv/yZ8U/pEWPFMLHw/RDCuS5fylacIUq5TuUymD7MTJ21udK0n1UnXuWc2QSA9bHAmbA
WeG4AlZX6nwy4TmB/c6/GXuwp9/hELoFIJ+mlfUttdwxNYRTTSHk6nNdDQ3gVHb6DTzP6a
Ld6/YwF2VxAh7wgU3vl+woIIIt8SFudUr9E8pXAAAAAwEAAQAAAQEAjKkcUoVQ2u66Otud
D9Oq95YJD6FR1ZzN7GgHXkA+8MtR/XLs4NMEfXFgZ0uMObuJlMkgE5Y8kq4G2bcMN2dDJ8
21PBEOXNCTCvCCF98z+M1JxCyw5GUzgAeVSDprnPXi9Eks1a2Gn3us3WlJf5CyK65zXUY8
vs54Uh8ZkLQnSjp3WMKi1IDAAagsf1QribP0qSdfWD+OoZ3AWXLRGN529vjyPIyxYSG68V
HpwsSKxah4J5J7o86586ZjWM/AKvLcxGgE+iJR/HGzrQd9fwies8IbN5O72ulClRORNTX2
bl4AR+ueys7TR8lJ3CuUKJP3bPjKvqT2o4GHVn2Gic/3oQAAAIEAwId3DITlSZ1MHEnzvS
NFROo1VqrwYl1x3hLb2IYCmSOXzlt5UQSs4a/qReoAoulLjooW5Na8q2EL078V1ISuem3h
E4C1aL81F1Px2UzdRBiflkuQC1FSxez3UH8XmIsSPeDO5qvPNPCHPN9BbbTj3utBseitIt
nXp1XxEAlAUkgAAACBANOCdgVD7PFQ4P3JyPXLar2ARcuWX2FfmsRaDRtTNTsSL2SE6Ico
MWsyu0XGxBYXbmAT91ogH/LXLTcerFISFgjOXPcTOTbZYoQzWFFXf6lr4277Rcz9S0NhbV
KEo0vdZ+jRuMXtTmnEPaU72JLL4Ht36RZH8bNhZRXF38m16Gn/AAAAgQDHTlfECu+IXDUc
EK50EOHAfdJWcQPG3kDhFuNFiYk3tytrK+tvx+ZUt/iN1VkmpKSnn4NIkypGnp8URYsxSK
k8ZYpURDgXaV5QSDav0Lub+SC8wlXEw5m/fPHgzClmk4xgGjIc3fgJYKT2f+UprcAlf3cM
IZOdthyU9ISB5NAvqQAAAA50ZXN0QGxvY2FsaG9zdAECAw==
-----END OPENSSH PRIVATE KEY-----"#;

    println!("PEM content length: {}", pem_content.len());
    
    // Extract base64 content using the rsa crate pattern
    let der_encoded = pem_content
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    println!("Base64 clean length: {}", der_encoded.len());
    println!("Base64 lean:'{}'", &der_encoded);
    
    let der = base64::decode(&der_encoded).expect("failed to decode base64 content");
    println!("DER length: {}", der.len());
    
    if der.len() >= 15 {
        println!("Magic bytes: {:?}", &der[..15]);
        println!("Expected: {:?}", b"openssh-key-v1\0");
        println!("Match: {}", &der[..15] == b"openssh-key-v1\0");
    }
    
    // Try parsing with the actual function
    let key = ssh_client::auth::key::PrivateKey::parse_pem(pem_content);
    println!("Parse result: {:?}", key);
}
