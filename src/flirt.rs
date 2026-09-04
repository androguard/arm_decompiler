//! Lightweight FLIRT-style library signature matching by exported symbol names.

use alloc::string::String;
use alloc::vec::Vec;

/// Known library → symbol prefixes / exact names.
const SIGNATURES: &[(&str, &[&str])] = &[
    ("libc", &["malloc", "free", "memcpy", "memset", "strlen", "strcmp", "printf", "sprintf", "snprintf", "open", "close", "read", "write", "pthread_create"]),
    ("libm", &["sin", "cos", "tan", "sqrt", "pow", "log", "exp", "floor", "ceil"]),
    ("openssl", &["SSL_CTX_new", "SSL_connect", "EVP_EncryptInit", "AES_encrypt", "RSA_public_encrypt", "BIO_new", "X509_verify"]),
    ("jni", &["JNI_OnLoad", "JNI_OnUnload", "Java_"]),
    ("zlib", &["deflate", "inflate", "compress", "uncompress", "crc32", "adler32"]),
    ("unity", &["il2cpp_", "UnityEngine", "mono_"]),
    ("flutter", &["FlutterEngine", "Dart_", "kDart"]),
    ("libcpp", &["_ZNSt", "__cxa_", "_ZTI", "_ZTV"]),
];

/// Match symbol names against known library stubs.
/// Returns `(library, symbol)` hits.
pub fn flirt_match_names(names: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in names {
        for &(lib, sigs) in SIGNATURES {
            for sig in sigs {
                if name == *sig || name.starts_with(sig) || name.contains(sig) {
                    out.push((String::from(lib), name.clone()));
                    break;
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    out.dedup();
    out
}
