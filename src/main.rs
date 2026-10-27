use clap::Parser;
use shamir_secret_sharing::ShamirSecretSharing;
use shamir_secret_sharing::num_bigint::{BigInt, Sign};

#[derive(Parser, Debug)]
#[command(author, version, about = "CLI Secret Sharing", long_about = None)]
struct Cli {
    /// Generate shares
    #[arg(short = 'g', long = "generate")]
    generate: bool,

    /// Compose shares
    #[arg(short = 'c', long = "compose")]
    compose: bool,

    /// Threshold (numeric)
    #[arg(short = 't', long = "threshold")]
    threshold: Option<usize>,

    /// Share amount
    #[arg(short = 's', long = "share-amount")]
    share_amount: Option<usize>,

    /// Value (secret string for generation, or share pieces for composition)
    #[arg(short = 'v', long = "value", num_args = 1..)]
    value: Vec<String>,
}

fn get_prime() -> BigInt {
    BigInt::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .unwrap()
}

fn parse_share_piece(piece: &str) -> Option<(usize, BigInt)> {
    let clean = piece.trim();
    let (id_str, val_str) = clean.split_once(':').or_else(|| clean.split_once('-'))?;
    let id = id_str.parse::<usize>().ok()?;
    let val = val_str.parse::<BigInt>().ok()?;
    Some((id, val))
}

fn is_valid_printable_secret(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        s.chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
    } else {
        false
    }
}

// Generate all permutations of k elements chosen from 1..=max_n
fn get_permutations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    let mut used = vec![false; n + 1];
    fn backtrack(
        n: usize,
        k: usize,
        current: &mut Vec<usize>,
        used: &mut Vec<bool>,
        result: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == k {
            result.push(current.clone());
            return;
        }
        for i in 1..=n {
            if !used[i] {
                used[i] = true;
                current.push(i);
                backtrack(n, k, current, used, result);
                current.pop();
                used[i] = false;
            }
        }
    }
    backtrack(n, k, &mut current, &mut used, &mut result);
    result
}

fn generate_shares(
    secret_str: &str,
    threshold: usize,
    share_amount: usize,
) -> Vec<(usize, BigInt)> {
    let secret = BigInt::from_bytes_be(Sign::Plus, secret_str.as_bytes());
    let sss = ShamirSecretSharing {
        threshold,
        share_amount,
        prime: get_prime(),
    };
    sss.split(secret)
}

fn recover_from_explicit_shares(explicit_shares: &[(usize, BigInt)], threshold: usize) -> String {
    let sss = ShamirSecretSharing {
        threshold,
        share_amount: threshold,
        prime: get_prime(),
    };
    let recovered_bigint = sss.recover(&explicit_shares[0..threshold]);
    let (_sign, bytes) = recovered_bigint.to_bytes_be();
    String::from_utf8_lossy(&bytes).to_string()
}

fn recover_from_raw_values(raw_values: &[BigInt], threshold: usize, max_id: usize) -> String {
    let sss = ShamirSecretSharing {
        threshold,
        share_amount: threshold,
        prime: get_prime(),
    };
    let perms = get_permutations(max_id, threshold);
    for perm in perms {
        let candidate_shares: Vec<(usize, BigInt)> = perm
            .iter()
            .zip(raw_values.iter().take(threshold))
            .map(|(&id, val)| (id, val.clone()))
            .collect();

        let recovered = sss.recover(&candidate_shares);
        let (_sign, bytes) = recovered.to_bytes_be();
        if is_valid_printable_secret(&bytes) {
            return String::from_utf8_lossy(&bytes).to_string();
        }
    }

    // Fallback to sequential 1..=threshold if no printable match found
    let candidate_shares: Vec<(usize, BigInt)> = (1..=threshold)
        .zip(raw_values.iter().take(threshold))
        .map(|(id, val)| (id, val.clone()))
        .collect();
    let recovered = sss.recover(&candidate_shares);
    let (_sign, bytes) = recovered.to_bytes_be();
    String::from_utf8_lossy(&bytes).to_string()
}

fn main() {
    let cli = Cli::parse();

    if cli.generate {
        let threshold = match cli.threshold {
            Some(t) => t,
            None => {
                eprintln!("Error: --threshold (-t) is required for generation.");
                std::process::exit(1);
            }
        };
        let share_amount = match cli.share_amount {
            Some(s) => s,
            None => {
                eprintln!("Error: --share-amount (-s) is required for generation.");
                std::process::exit(1);
            }
        };
        if cli.value.is_empty() {
            eprintln!("Error: --value (-v) is required for generation.");
            std::process::exit(1);
        }

        let secret_str = cli.value.join(" ");
        let shares = generate_shares(&secret_str, threshold, share_amount);
        println!("Generated shares:");
        for (id, val) in shares {
            println!("{}:{}", id, val);
        }
    } else if cli.compose {
        let threshold = match cli.threshold {
            Some(t) => t,
            None => {
                eprintln!("Error: --threshold (-t) is required for composition.");
                std::process::exit(1);
            }
        };
        if cli.value.is_empty() {
            eprintln!("Error: --value (-v) with share pieces is required for composition.");
            std::process::exit(1);
        }

        if cli.value.len() < threshold {
            eprintln!(
                "Error: Provided {} shares, but threshold is {}.",
                cli.value.len(),
                threshold
            );
            std::process::exit(1);
        }

        // Check if any shares have explicit id (e.g. 1:... or 1-...)
        let mut explicit_shares = Vec::new();
        let mut raw_values = Vec::new();
        for piece in &cli.value {
            if let Some((id, val)) = parse_share_piece(piece) {
                explicit_shares.push((id, val));
            } else if let Ok(val) = piece.parse::<BigInt>() {
                raw_values.push(val);
            } else {
                eprintln!("Error: Invalid share piece '{}'", piece);
                std::process::exit(1);
            }
        }

        if explicit_shares.len() >= threshold {
            let original_value = recover_from_explicit_shares(&explicit_shares, threshold);
            println!("Original value: {}", original_value);
        } else if !raw_values.is_empty() {
            let max_id = cli.share_amount.unwrap_or(20).max(10);
            let original_value = recover_from_raw_values(&raw_values, threshold, max_id);
            println!("Original value: {}", original_value);
        } else {
            eprintln!("Error: Could not parse shares from --value.");
            std::process::exit(1);
        }
    } else {
        println!(
            "Please specify either -g (--generate) or -c (--compose). Use --help for usage details."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_share_piece_colon() {
        let parsed = parse_share_piece("1:1234567890");
        assert!(parsed.is_some());
        let (id, val) = parsed.unwrap();
        assert_eq!(id, 1);
        assert_eq!(val, BigInt::from(1234567890i64));
    }

    #[test]
    fn test_parse_share_piece_hyphen() {
        let parsed = parse_share_piece("3-987654321");
        assert!(parsed.is_some());
        let (id, val) = parsed.unwrap();
        assert_eq!(id, 3);
        assert_eq!(val, BigInt::from(987654321i64));
    }

    #[test]
    fn test_parse_share_piece_with_whitespace() {
        let parsed = parse_share_piece("  4:42  ");
        assert!(parsed.is_some());
        let (id, val) = parsed.unwrap();
        assert_eq!(id, 4);
        assert_eq!(val, BigInt::from(42));
    }

    #[test]
    fn test_parse_share_piece_invalid() {
        assert!(parse_share_piece("").is_none());
        assert!(parse_share_piece("12345").is_none());
        assert!(parse_share_piece("abc:123").is_none());
        assert!(parse_share_piece("1:abc").is_none());
        assert!(parse_share_piece(":123").is_none());
        assert!(parse_share_piece("1:").is_none());
    }

    #[test]
    fn test_is_valid_printable_secret() {
        assert!(is_valid_printable_secret(b"MySecretPassword123!"));
        assert!(is_valid_printable_secret(b"Line1\nLine2\tTab\r"));
        assert!(!is_valid_printable_secret(b""));
        assert!(!is_valid_printable_secret(b"invalid\x00control"));
        assert!(!is_valid_printable_secret(b"bell\x07character"));
        assert!(!is_valid_printable_secret(&[0xFF, 0xFE, 0xFD]));
    }

    #[test]
    fn test_get_permutations() {
        let perms = get_permutations(3, 2);
        // P(3, 2) = 3! / (3-2)! = 6
        assert_eq!(perms.len(), 6);
        for p in &perms {
            assert_eq!(p.len(), 2);
            assert!(p[0] >= 1 && p[0] <= 3);
            assert!(p[1] >= 1 && p[1] <= 3);
            assert_ne!(p[0], p[1]);
        }

        let perms_full = get_permutations(3, 3);
        // P(3, 3) = 3! = 6
        assert_eq!(perms_full.len(), 6);

        let perms_empty = get_permutations(3, 0);
        assert_eq!(perms_empty.len(), 1);
        assert!(perms_empty[0].is_empty());
    }

    #[test]
    fn test_generate_and_recover_explicit_shares() {
        let secret = "SuperSecretBreakGlassKey2026!";
        let threshold = 3;
        let share_amount = 5;

        let shares = generate_shares(secret, threshold, share_amount);
        assert_eq!(shares.len(), 5);

        // Check share IDs are 1..=5
        for (i, (id, _val)) in shares.iter().enumerate() {
            assert_eq!(*id, i + 1);
        }

        // Recover with shares 1, 2, 3
        let subset1 = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let recovered1 = recover_from_explicit_shares(&subset1, threshold);
        assert_eq!(recovered1, secret);

        // Recover with shares 2, 4, 5
        let subset2 = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered2 = recover_from_explicit_shares(&subset2, threshold);
        assert_eq!(recovered2, secret);

        // Recover with shares 1, 3, 5
        let subset3 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered3 = recover_from_explicit_shares(&subset3, threshold);
        assert_eq!(recovered3, secret);
    }

    #[test]
    fn test_recover_from_raw_values_with_permutation_search() {
        let secret = "BreakTheGlassPassword999";
        let threshold = 3;
        let share_amount = 5;

        let shares = generate_shares(secret, threshold, share_amount);

        // Take shares with IDs 2, 4, 5 but stripped of IDs (only raw BigInt values)
        let raw_values = vec![
            shares[1].1.clone(),
            shares[3].1.clone(),
            shares[4].1.clone(),
        ];

        let recovered = recover_from_raw_values(&raw_values, threshold, share_amount);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_unicode_secret_handling() {
        let secret = "Segreto-Sicurissimo-123_456";
        let threshold = 2;
        let share_amount = 3;

        let shares = generate_shares(secret, threshold, share_amount);
        assert_eq!(shares.len(), 3);

        let recovered = recover_from_explicit_shares(&shares[0..2], threshold);
        assert_eq!(recovered, secret);
    }
}
