//! The `crypto` IOC-type module: cryptocurrency wallet addresses.
//!
//! Detection is by format plus checksum where it is feasible without heavy
//! dependencies:
//! - **BTC** legacy (`1…`/`3…`): full Base58Check (double-SHA256) validation.
//! - **BTC** segwit (`bc1…`): full bech32/bech32m checksum validation.
//! - **ETH** (`0x` + 40 hex): format only — EIP-55 needs keccak, and
//!   all-lowercase addresses (the common IOC form) carry no case checksum.
//! - **XMR** (95/106 chars, `4…`/`8…`): format only — the checksum also
//!   requires keccak.

use super::{Detection, IocModule};
use crate::model::indicator::IndicatorType;
use sha2::{Digest, Sha256};

pub struct CryptoModule;

impl IocModule for CryptoModule {
    fn name(&self) -> &str {
        "crypto"
    }

    fn handles(&self) -> Vec<IndicatorType> {
        vec![IndicatorType::Btc, IndicatorType::Eth, IndicatorType::Xmr]
    }

    fn detect(&self, raw: &str) -> Option<Detection> {
        let v = raw.trim();

        // ETH — unambiguous prefix, checked first.
        if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            if hex.len() == 40 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(Detection {
                    indicator_type: IndicatorType::Eth,
                    canonical: v.to_lowercase(),
                });
            }
            return None;
        }

        // BTC segwit — bech32 is case-insensitive but must not be mixed-case.
        let lower = v.to_lowercase();
        if lower.starts_with("bc1")
            && (v == lower || v == v.to_uppercase())
            && bech32_checksum_ok(&lower)
        {
            return Some(Detection {
                indicator_type: IndicatorType::Btc,
                canonical: lower,
            });
        }

        // BTC legacy — Base58Check pins down what a prefix + length can't.
        if (v.starts_with('1') || v.starts_with('3'))
            && (25..=35).contains(&v.len())
            && base58check_ok(v)
        {
            return Some(Detection {
                indicator_type: IndicatorType::Btc,
                canonical: v.to_string(),
            });
        }

        // XMR — standard (95) or integrated (106) address.
        if (v.starts_with('4') || v.starts_with('8'))
            && (v.len() == 95 || v.len() == 106)
            && v.chars().all(is_base58_char)
        {
            return Some(Detection {
                indicator_type: IndicatorType::Xmr,
                canonical: v.to_string(),
            });
        }

        None
    }
}

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn is_base58_char(c: char) -> bool {
    c.is_ascii() && BASE58.contains(&(c as u8))
}

/// Decode a base58 string to bytes (big-endian), or `None` on a bad character.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new(); // little-endian accumulator
    for ch in s.bytes() {
        let mut carry = BASE58.iter().position(|&c| c == ch)? as u32;
        for b in bytes.iter_mut() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Each leading '1' encodes a leading zero byte.
    bytes.extend(s.bytes().take_while(|&c| c == b'1').map(|_| 0));
    bytes.reverse();
    Some(bytes)
}

/// Base58Check: 25 decoded bytes whose last 4 match the double-SHA256 of the rest.
fn base58check_ok(s: &str) -> bool {
    let Some(bytes) = base58_decode(s) else {
        return false;
    };
    if bytes.len() != 25 {
        return false;
    }
    let (payload, checksum) = bytes.split_at(21);
    let digest = Sha256::digest(Sha256::digest(payload));
    digest[..4] == *checksum
}

const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// BIP-173/350 checksum over an all-lowercase candidate; accepts both the
/// bech32 (segwit v0) and bech32m (v1+/taproot) constants.
fn bech32_checksum_ok(s: &str) -> bool {
    let Some(pos) = s.rfind('1') else {
        return false;
    };
    let (hrp, data) = (&s[..pos], &s[pos + 1..]);
    if hrp.is_empty() || data.len() < 6 {
        return false;
    }

    let gen = [
        0x3b6a_57b2u32,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    let mut step = |value: u32| {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ value;
        for (i, g) in gen.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    };

    for b in hrp.bytes() {
        step((b >> 5) as u32);
    }
    step(0);
    for b in hrp.bytes() {
        step((b & 31) as u32);
    }
    for c in data.chars() {
        let Some(v) = BECH32_CHARSET.find(c) else {
            return false;
        };
        step(v as u32);
    }
    chk == 1 || chk == BECH32M_CONST
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(raw: &str) -> Option<(IndicatorType, String)> {
        CryptoModule
            .detect(raw)
            .map(|d| (d.indicator_type, d.canonical))
    }

    #[test]
    fn detects_btc_legacy_with_valid_checksum() {
        // The genesis block address.
        assert_eq!(
            detect("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").map(|(t, _)| t),
            Some(IndicatorType::Btc)
        );
        // P2SH form.
        assert_eq!(
            detect("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").map(|(t, _)| t),
            Some(IndicatorType::Btc)
        );
    }

    #[test]
    fn rejects_btc_legacy_with_bad_checksum() {
        // Last character flipped.
        assert_eq!(detect("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"), None);
    }

    #[test]
    fn detects_btc_bech32_and_lowercases() {
        // BIP-173 test vector.
        assert_eq!(
            detect("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").map(|(t, _)| t),
            Some(IndicatorType::Btc)
        );
        assert_eq!(
            detect("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ").map(|(_, c)| c),
            Some("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string())
        );
        // Corrupted data part.
        assert_eq!(detect("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx"), None);
    }

    #[test]
    fn detects_eth_and_lowercases() {
        assert_eq!(
            detect("0x7F367cC41522cE07553e823bf3be79A889DEbe1B"),
            Some((
                IndicatorType::Eth,
                "0x7f367cc41522ce07553e823bf3be79a889debe1b".to_string()
            ))
        );
        assert_eq!(detect("0x7f367cc41522ce07553e823bf3be79a889debe1"), None); // 39 hex
    }

    #[test]
    fn detects_xmr_by_format() {
        let addr = format!("4{}", "A".repeat(94));
        assert_eq!(detect(&addr).map(|(t, _)| t), Some(IndicatorType::Xmr));
        assert_eq!(detect(&format!("4{}", "A".repeat(93))), None); // wrong length
        assert_eq!(detect(&format!("4{}O", "A".repeat(93))), None); // 'O' not base58
    }

    #[test]
    fn rejects_junk() {
        assert_eq!(detect(""), None);
        assert_eq!(detect("hello world"), None);
        assert_eq!(detect("1234"), None);
    }
}
