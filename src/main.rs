use clap::Parser;
use shamir_secret_sharing::num_bigint::{BigInt, Sign};
use shamir_secret_sharing::ShamirSecretSharing;

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

fn parse_share_piece(piece: &str) -> Option<(usize, BigInt)> {
    let clean = piece.trim();
    if let Some((id_str, val_str)) = clean.split_once(':').or_else(|| clean.split_once('-')) {
        if let Ok(id) = id_str.parse::<usize>() {
            if let Ok(val) = val_str.parse::<BigInt>() {
                return Some((id, val));
            }
        }
    }
    None
}

fn is_valid_printable_secret(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
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

fn main() {
    let cli = Cli::parse();

    // Standard large prime (secp256k1 prime)
    let prime = BigInt::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .unwrap();

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
        let secret = BigInt::from_bytes_be(Sign::Plus, secret_str.as_bytes());

        let sss = ShamirSecretSharing {
            threshold,
            share_amount,
            prime,
        };

        let shares = sss.split(secret);
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

        let sss = ShamirSecretSharing {
            threshold,
            share_amount: threshold,
            prime: prime.clone(),
        };

        if explicit_shares.len() >= threshold {
            let recovered_bigint = sss.recover(&explicit_shares[0..threshold]);
            let (_sign, bytes) = recovered_bigint.to_bytes_be();
            let original_value = String::from_utf8_lossy(&bytes);
            println!("Original value: {}", original_value);
        } else if !raw_values.is_empty() {
            // Raw values provided without ID.
            // Determine search range for share IDs.
            let max_id = cli.share_amount.unwrap_or(20).max(10);
            let perms = get_permutations(max_id, threshold);
            let mut found_secret = None;

            for perm in perms {
                let candidate_shares: Vec<(usize, BigInt)> = perm
                    .iter()
                    .zip(raw_values.iter().take(threshold))
                    .map(|(&id, val)| (id, val.clone()))
                    .collect();

                let recovered = sss.recover(&candidate_shares);
                let (_sign, bytes) = recovered.to_bytes_be();
                if is_valid_printable_secret(&bytes) {
                    found_secret = Some(String::from_utf8_lossy(&bytes).to_string());
                    break;
                }
            }

            match found_secret {
                Some(secret) => {
                    println!("Original value: {}", secret);
                }
                None => {
                    // Fallback to sequential 1..=threshold if no printable match found
                    let candidate_shares: Vec<(usize, BigInt)> = (1..=threshold)
                        .zip(raw_values.iter().take(threshold))
                        .map(|(id, val)| (id, val.clone()))
                        .collect();
                    let recovered = sss.recover(&candidate_shares);
                    let (_sign, bytes) = recovered.to_bytes_be();
                    println!("Original value: {}", String::from_utf8_lossy(&bytes));
                }
            }
        } else {
            eprintln!("Error: Could not parse shares from --value.");
            std::process::exit(1);
        }
    } else {
        println!("Please specify either -g (--generate) or -c (--compose). Use --help for usage details.");
    }
}
