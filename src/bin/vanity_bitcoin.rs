use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use bech32::{self, ToBase32, Variant};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use clap::{Parser, ValueEnum};
use once_cell::sync::Lazy;
use rand::Rng;
use rayon::ThreadPoolBuilder;
use ripemd::Ripemd160;
use secp256k1::{All, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ATTEMPT_BATCH: u64 = 2048;
const PROGRESS_INTERVAL: u64 = 100_000;
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(Secp256k1::new);

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
enum AddressFormat {
    P2pkh,
    Bech32,
}

#[derive(Parser, Debug)]
#[command(name = "vanity_bitcoin")]
#[command(about = "Brute force Bitcoin vanity addresses", long_about = None)]
struct Args {
    #[arg(long, value_enum, default_value_t = AddressFormat::P2pkh)]
    format: AddressFormat,
    #[arg(long, default_value_t = 0)]
    witness_version: u8,
    #[arg(long)]
    prefix: Option<String>,

    #[arg(long)]
    suffix: Option<String>,

    #[arg(long, default_value_t = 0)]
    attempts: u64,

    #[arg(long)]
    threads: Option<usize>,

    #[arg(long)]
    seed: Option<u64>,

    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long)]
    checkpoint: Option<PathBuf>,

    #[arg(long)]
    resume: Option<PathBuf>,

    #[arg(long, default_value_t = 100_000)]
    checkpoint_interval: u64,

    #[arg(long)]
    mnemonic: bool,

    #[arg(long, default_value = "m/44'/0'/0'/0/0")]
    hd_path: String,

    #[arg(long)]
    derive_attempt: Option<u64>,

    #[arg(long, default_value_t = 5)]
    stats_interval: u64,

    #[arg(long)]
    stats_json: bool,
}

#[derive(Serialize)]
struct VanityResult {
    private_key_hex: String,
    wif: String,
    address: String,
    format: String,
    witness_version: Option<u8>,
    attempts: u64,
    attempts_limit: Option<u64>,
    seed: u64,
    prefix: Option<String>,
    suffix: Option<String>,
    mnemonic: Option<String>,
    hd_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CheckpointFile {
    version: u32,
    next_attempt: u64,
    base_seed: u64,
    config_hash: String,
}

struct CheckpointWriter {
    path: PathBuf,
    config_hash: String,
    base_seed: u64,
    interval: u64,
    next_flush: AtomicU64,
    lock: Mutex<()>,
}

impl CheckpointWriter {
    fn new(path: PathBuf, config_hash: String, base_seed: u64, interval: u64) -> Self {
        Self {
            path,
            config_hash,
            base_seed,
            interval: interval.max(1),
            next_flush: AtomicU64::new(0),
            lock: Mutex::new(()),
        }
    }

    fn maybe_write(&self, attempts: u64) {
        let target = self.next_flush.load(Ordering::Relaxed);
        if attempts < target {
            return;
        }
        if let Ok(_guard) = self.lock.try_lock() {
            let target = self.next_flush.load(Ordering::Relaxed);
            if attempts < target {
                return;
            }
            if let Err(err) = self.write_file(attempts) {
                eprintln!(
                    "Failed to write checkpoint {}: {err:?}",
                    self.path.display()
                );
            } else {
                let next = attempts.saturating_add(self.interval);
                self.next_flush.store(next, Ordering::Relaxed);
            }
        }
    }

    fn force_write(&self, attempts: u64) -> Result<()> {
        let _guard = self.lock.lock().expect("checkpoint mutex poisoned");
        self.write_file(attempts)?;
        let next = attempts.saturating_add(self.interval);
        self.next_flush.store(next, Ordering::Relaxed);
        Ok(())
    }

    fn write_file(&self, attempts: u64) -> Result<()> {
        let payload = CheckpointFile {
            version: 1,
            next_attempt: attempts,
            base_seed: self.base_seed,
            config_hash: self.config_hash.clone(),
        };
        save_checkpoint_file(&self.path, &payload)
    }
}

#[derive(Serialize)]
struct ProgressStats {
    attempts: u64,
    attempts_per_sec: f64,
    elapsed_ms: u128,
}

#[derive(Clone)]
enum KeyMode {
    Raw,
    Mnemonic {
        path: DerivationPath,
        path_string: String,
    },
}

struct CandidateKey {
    secret: SecretKey,
    mnemonic: Option<String>,
}

impl KeyMode {
    fn path_string(&self) -> Option<&str> {
        match self {
            KeyMode::Raw => None,
            KeyMode::Mnemonic { path_string, .. } => Some(path_string.as_str()),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.witness_version > 16 {
        return Err(anyhow!("--witness-version must be between 0 and 16"));
    }
    if args.format != AddressFormat::Bech32 && args.witness_version != 0 {
        return Err(anyhow!(
            "--witness-version only applies when --format bech32"
        ));
    }

    let max_attempts = if args.attempts == 0 {
        u64::MAX
    } else {
        args.attempts
    };

    let threads = args
        .threads
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1)
        .max(1);
    let provided_seed = args.seed;
    let mut base_seed = provided_seed.unwrap_or_else(|| rand::thread_rng().gen());
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("results/vanity-bitcoin.json"));

    let key_mode = if args.mnemonic {
        let path = DerivationPath::from_str(&args.hd_path).with_context(|| {
            format!("Invalid --hd-path '{}': expected BIP32 path", args.hd_path)
        })?;
        KeyMode::Mnemonic {
            path,
            path_string: args.hd_path.clone(),
        }
    } else {
        KeyMode::Raw
    };
    let key_mode = Arc::new(key_mode);

    if let Some(target_attempt) = args.derive_attempt {
        if provided_seed.is_none() {
            return Err(anyhow!("--derive-attempt requires --seed"));
        }
        let candidate = derive_candidate(base_seed, target_attempt, key_mode.as_ref())
            .ok_or_else(|| anyhow!("Failed to derive attempt {}", target_attempt))?;
        let mut address_buf = String::with_capacity(40);
        encode_address(
            &candidate.secret,
            args.format,
            args.witness_version,
            &mut address_buf,
        )?;
        println!("Derived attempt {}", target_attempt);
        print_candidate(
            &candidate,
            &address_buf,
            key_mode.as_ref(),
            args.format,
            args.witness_version,
        );
        return Ok(());
    }

    let prefix = prepare_pattern(args.prefix.clone(), args.format)?;
    let suffix = prepare_pattern(args.suffix.clone(), args.format)?;
    if prefix.is_none() && suffix.is_none() {
        return Err(anyhow!("Provide --prefix and/or --suffix"));
    }

    let mut resume_attempt = 0u64;
    let resume_checkpoint = if let Some(path) = args.resume.as_ref() {
        Some((
            path.clone(),
            load_checkpoint_file(path)
                .with_context(|| format!("Failed to load checkpoint at {}", path.display()))?,
        ))
    } else {
        None
    };

    if let Some((_, checkpoint)) = &resume_checkpoint {
        if let Some(seed) = args.seed {
            if seed != checkpoint.base_seed {
                return Err(anyhow!(
                    "Checkpoint base seed ({}) does not match --seed ({})",
                    checkpoint.base_seed,
                    seed
                ));
            }
        }
        base_seed = checkpoint.base_seed;
        resume_attempt = checkpoint.next_attempt;
    }

    let config_hash = hex::encode(config_fingerprint(
        base_seed,
        &prefix,
        &suffix,
        key_mode.as_ref(),
        args.format,
        args.witness_version,
    ));

    if let Some((_, checkpoint)) = &resume_checkpoint {
        if checkpoint.config_hash != config_hash {
            return Err(anyhow!(
                "Checkpoint was created for different search parameters."
            ));
        }
    }

    if resume_attempt >= max_attempts {
        println!("Checkpoint already exhausted the requested attempt budget.");
        return Ok(());
    }

    println!("Searching for Bitcoin vanity key ({:?})...", args.format);
    if let Some(p) = &prefix {
        println!("Prefix    : {}", p);
    }
    if let Some(s) = &suffix {
        println!("Suffix    : {}", s);
    }
    let max_display = if max_attempts == u64::MAX {
        "∞".to_string()
    } else {
        max_attempts.to_string()
    };
    println!("Max tries : {}", max_display);
    println!("Threads   : {}", threads);
    match (&resume_checkpoint, args.seed) {
        (Some(_), _) => println!("RNG seed  : {} (from checkpoint)", base_seed),
        (None, Some(seed)) => println!("RNG seed  : {} (user supplied)", seed),
        (None, None) => println!("RNG seed  : {} (randomized)", base_seed),
    }
    println!("Output    : {}", output_path.display());
    match key_mode.as_ref() {
        KeyMode::Raw => println!("Mode      : raw private keys"),
        KeyMode::Mnemonic { path_string, .. } => {
            println!("Mode      : BIP-39 mnemonic (path {})", path_string)
        }
    }
    if args.format == AddressFormat::Bech32 {
        println!(
            "Witness   : version {} ({})",
            args.witness_version,
            if args.witness_version == 0 {
                "Bech32"
            } else {
                "Bech32m"
            }
        );
    }
    if resume_attempt > 0 {
        println!("Start at  : attempt {}", resume_attempt);
    }
    if let Some((path, _)) = &resume_checkpoint {
        println!("Resume    : {}", path.display());
    }
    if let Some(path) = &args.checkpoint {
        println!(
            "Checkpoint : {} (every {} attempts)",
            path.display(),
            args.checkpoint_interval.max(1)
        );
    }
    if args.stats_interval > 0 {
        println!(
            "Stats     : every {}s ({})",
            args.stats_interval,
            if args.stats_json { "json" } else { "text" }
        );
    }

    let checkpoint_writer = if let Some(path) = args.checkpoint.clone() {
        if args.checkpoint_interval == 0 {
            return Err(anyhow!("--checkpoint-interval must be greater than 0"));
        }
        let writer = Arc::new(CheckpointWriter::new(
            path,
            config_hash.clone(),
            base_seed,
            args.checkpoint_interval,
        ));
        writer.force_write(resume_attempt)?;
        Some(writer)
    } else {
        None
    };

    let start = Instant::now();
    let scheduler = Arc::new(AtomicU64::new(resume_attempt));
    let attempts_done = Arc::new(AtomicU64::new(resume_attempt));
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));
    let stats_stop = Arc::new(AtomicBool::new(false));
    let stats_handle = spawn_stats_thread(
        args.stats_interval,
        args.stats_json,
        Arc::clone(&attempts_done),
        Arc::clone(&stats_stop),
        start,
    );

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .context("Failed to build rayon thread pool")?;

    pool.install(|| {
        rayon::scope(|s| {
            for worker_idx in 0..threads {
                let scheduler = Arc::clone(&scheduler);
                let attempts_done = Arc::clone(&attempts_done);
                let found = Arc::clone(&found);
                let result = Arc::clone(&result);
                let prefix = prefix.clone();
                let suffix = suffix.clone();
                let checkpoint = checkpoint_writer.clone();
                let key_mode = Arc::clone(&key_mode);

                s.spawn(move |_| {
                    let mut stop = false;
                    let mut address_buf = String::with_capacity(40);

                    while !stop {
                        if found.load(Ordering::Acquire) {
                            break;
                        }

                        let start = scheduler.fetch_add(ATTEMPT_BATCH, Ordering::Relaxed);
                        if start >= max_attempts {
                            break;
                        }

                        let end = (start + ATTEMPT_BATCH).min(max_attempts);
                        let mut processed = 0u64;

                        for attempt in start..end {
                            if found.load(Ordering::Acquire) {
                                stop = true;
                                break;
                            }

                            if worker_idx == 0 && attempt != 0 && attempt % PROGRESS_INTERVAL == 0 {
                                println!("Checked {} keys...", attempt);
                            }

                            processed += 1;

                            let attempt_number = attempt;
                            let candidate = match derive_candidate(
                                base_seed,
                                attempt_number,
                                key_mode.as_ref(),
                            ) {
                                Some(value) => value,
                                None => continue,
                            };
                            if encode_address(
                                &candidate.secret,
                                args.format,
                                args.witness_version,
                                &mut address_buf,
                            )
                            .is_err()
                            {
                                continue;
                            }

                            if matches_pattern(&address_buf, prefix.as_deref(), suffix.as_deref()) {
                                let mut guard = result.lock().expect("poisoned mutex");
                                *guard = Some((candidate, address_buf.clone(), attempt_number + 1));
                                found.store(true, Ordering::Release);
                                stop = true;
                                break;
                            }
                        }

                        if processed != 0 {
                            let total =
                                attempts_done.fetch_add(processed, Ordering::Relaxed) + processed;
                            if let Some(writer) = checkpoint.as_ref() {
                                writer.maybe_write(total);
                            }
                        }

                        if stop {
                            break;
                        }
                    }
                });
            }
        });
    });

    stats_stop.store(true, Ordering::Release);
    if let Some(handle) = stats_handle {
        let _ = handle.join();
    }

    let elapsed = start.elapsed();
    let attempts_made = attempts_done.load(Ordering::Relaxed).min(max_attempts);
    if let Some((candidate, address, attempts_needed)) = result.lock().unwrap().take() {
        println!();
        println!(
            "Found vanity key after {} attempts ({:.2?})",
            attempts_needed, elapsed
        );
        print_candidate(
            &candidate,
            &address,
            key_mode.as_ref(),
            args.format,
            args.witness_version,
        );

        let report = VanityResult {
            private_key_hex: format!("0x{}", hex::encode(candidate.secret.secret_bytes())),
            wif: wif_from_secret(&candidate.secret),
            address,
            format: format!("{:?}", args.format),
            witness_version: (args.format == AddressFormat::Bech32).then_some(args.witness_version),
            attempts: attempts_needed,
            attempts_limit: if max_attempts == u64::MAX {
                None
            } else {
                Some(max_attempts)
            },
            seed: base_seed,
            prefix,
            suffix,
            mnemonic: candidate.mnemonic.clone(),
            hd_path: key_mode.as_ref().path_string().map(|s| s.to_string()),
        };
        match append_result_file(&output_path, &report) {
            Ok(_) => println!("Result saved to {}", output_path.display()),
            Err(err) => eprintln!(
                "Failed to write result file {}: {err:?}",
                output_path.display()
            ),
        }
    } else {
        println!();
        println!(
            "No vanity key found after {} attempts ({:.2?}). Increase --attempts or relax prefix/suffix.",
            attempts_made, elapsed
        );
    }

    if let Some(writer) = checkpoint_writer.as_ref() {
        writer.force_write(attempts_made)?;
    }

    Ok(())
}

fn print_candidate(
    candidate: &CandidateKey,
    address: &str,
    mode: &KeyMode,
    format: AddressFormat,
    witness_version: u8,
) {
    let secret_hex = hex::encode(candidate.secret.secret_bytes());
    let wif = wif_from_secret(&candidate.secret);
    match format {
        AddressFormat::Bech32 => {
            println!(
                "Address   : {} ({:?} v{})",
                address, format, witness_version
            );
        }
        _ => println!("Address   : {} ({:?})", address, format),
    }
    println!("SecretHex : 0x{}", secret_hex);
    println!("WIF       : {}", wif);
    if let Some(phrase) = candidate.mnemonic.as_ref() {
        println!("Mnemonic  : {}", phrase);
        if let KeyMode::Mnemonic { path_string, .. } = mode {
            println!("HD path   : {}", path_string);
        }
    }
}

fn prepare_pattern(pattern: Option<String>, format: AddressFormat) -> Result<Option<String>> {
    pattern
        .map(|value| {
            let normalized = match format {
                AddressFormat::P2pkh => value,
                AddressFormat::Bech32 => value.to_lowercase(),
            };
            ensure_charset(&normalized, format)?;
            Ok(normalized)
        })
        .transpose()
}

fn ensure_charset(value: &str, format: AddressFormat) -> Result<()> {
    let valid = match format {
        AddressFormat::P2pkh => value.chars().all(
            |c| matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'),
        ),
        AddressFormat::Bech32 => value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='z')),
    };
    if valid {
        return Ok(());
    }

    let note = match format {
        AddressFormat::P2pkh => "Base58 characters (no 0 O I l)",
        AddressFormat::Bech32 => "lowercase Bech32 characters",
    };
    Err(anyhow!(
        "Pattern '{}' contains invalid characters for {:?} ({})",
        value,
        format,
        note
    ))
}

fn matches_pattern(address: &str, prefix: Option<&str>, suffix: Option<&str>) -> bool {
    if let Some(p) = prefix {
        if !address.starts_with(p) {
            return false;
        }
    }
    if let Some(s) = suffix {
        if !address.ends_with(s) {
            return false;
        }
    }
    true
}

fn derive_candidate(base_seed: u64, attempt: u64, mode: &KeyMode) -> Option<CandidateKey> {
    match mode {
        KeyMode::Raw => {
            let material = key_material_from_attempt(base_seed, attempt);
            let secret = SecretKey::from_slice(&material).ok()?;
            Some(CandidateKey {
                secret,
                mnemonic: None,
            })
        }
        KeyMode::Mnemonic { path, .. } => {
            let entropy = key_material_from_attempt(base_seed, attempt);
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).ok()?;
            let phrase = mnemonic.to_string();
            let seed = mnemonic.to_seed("");
            let child = XPrv::derive_from_path(&seed, path).ok()?;
            let signing_key = child.private_key();
            let secret = SecretKey::from_slice(&signing_key.to_bytes()).ok()?;
            Some(CandidateKey {
                secret,
                mnemonic: Some(phrase),
            })
        }
    }
}

fn key_material_from_attempt(base_seed: u64, attempt: u64) -> [u8; 32] {
    let mut state = base_seed ^ attempt;
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        state = splitmix64(state);
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    out
}

fn encode_address(
    secret: &SecretKey,
    format: AddressFormat,
    witness_version: u8,
    out: &mut String,
) -> Result<()> {
    match format {
        AddressFormat::P2pkh => {
            let public = SecpPublicKey::from_secret_key(&SECP256K1, secret);
            let pub_bytes = public.serialize();
            let sha = Sha256::digest(pub_bytes);
            let rip = Ripemd160::digest(&sha);
            let mut payload = Vec::with_capacity(25);
            payload.push(0x00);
            payload.extend_from_slice(&rip);
            let checksum = double_sha256(&payload);
            payload.extend_from_slice(&checksum[..4]);
            encode_base58(&payload, out);
            Ok(())
        }
        AddressFormat::Bech32 => {
            let public = SecpPublicKey::from_secret_key(&SECP256K1, secret);
            let program = match witness_version {
                0 => {
                    let pub_bytes = public.serialize();
                    let sha = Sha256::digest(pub_bytes);
                    Ripemd160::digest(&sha).to_vec()
                }
                1 => {
                    let pub_bytes = public.serialize();
                    pub_bytes[1..].to_vec()
                }
                other => {
                    return Err(anyhow!(
                        "Witness version {} not supported (only v0 or v1)",
                        other
                    ));
                }
            };
            let variant = if witness_version == 0 {
                Variant::Bech32
            } else {
                Variant::Bech32m
            };
            let mut data = Vec::with_capacity(1 + program.len());
            let version_u5 = bech32::u5::try_from_u8(witness_version)
                .map_err(|e| anyhow!("Invalid witness version: {e}"))?;
            data.push(version_u5);
            data.extend(program.to_base32());
            let addr = bech32::encode("bc", data, variant)
                .map_err(|e| anyhow!("bech32 encode failed: {e}"))?;
            out.clear();
            out.push_str(&addr);
            Ok(())
        }
    }
}

fn wif_from_secret(secret: &SecretKey) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(0x80);
    payload.extend_from_slice(&secret.secret_bytes());
    payload.push(0x01); // compressed
    let checksum = double_sha256(&payload);
    let mut buf = payload;
    buf.extend_from_slice(&checksum[..4]);
    let mut out = String::with_capacity(52);
    encode_base58(&buf, &mut out);
    out
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn encode_base58(input: &[u8], out: &mut String) {
    // 138/100 is enough slack to Base58-encode arbitrary data (Bitcoin reference logic).
    let capacity = (input.len() * 138 / 100) + 1;
    let mut digits = vec![0u8; capacity.max(1)];
    let mut digit_len = 1;

    for &byte in input {
        let mut carry = byte as u32;
        for digit in digits[..digit_len].iter_mut() {
            let val = (*digit as u32) * 256 + carry;
            *digit = (val % 58) as u8;
            carry = val / 58;
        }
        while carry > 0 {
            if digit_len >= digits.len() {
                digits.push(0);
            }
            digits[digit_len] = (carry % 58) as u8;
            carry /= 58;
            digit_len += 1;
        }
    }

    let mut zeros = 0;
    for b in input {
        if *b == 0 {
            zeros += 1;
        } else {
            break;
        }
    }

    out.clear();
    out.reserve(zeros + digit_len);
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits[..digit_len].iter().rev() {
        out.push(BASE58_ALPHABET[*digit as usize] as char);
    }
    if out.is_empty() {
        out.push('1');
    }
}

fn config_fingerprint(
    base_seed: u64,
    prefix: &Option<String>,
    suffix: &Option<String>,
    mode: &KeyMode,
    format: AddressFormat,
    witness_version: u8,
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&base_seed.to_le_bytes());
    if let Some(p) = prefix {
        data.extend_from_slice(p.as_bytes());
        data.push(0xff);
    }
    if let Some(s) = suffix {
        data.extend_from_slice(s.as_bytes());
        data.push(0x01);
    }
    match mode {
        KeyMode::Raw => data.push(0x10),
        KeyMode::Mnemonic { path_string, .. } => {
            data.push(0x22);
            data.extend_from_slice(path_string.as_bytes());
        }
    }
    match format {
        AddressFormat::P2pkh => data.push(0x01),
        AddressFormat::Bech32 => {
            data.push(0x02);
            data.push(witness_version);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let first = hasher.finalize();
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn spawn_stats_thread(
    interval_secs: u64,
    json_mode: bool,
    attempts_done: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    start: Instant,
) -> Option<thread::JoinHandle<()>> {
    if interval_secs == 0 {
        return None;
    }
    let interval = Duration::from_secs(interval_secs.max(1));
    Some(thread::spawn(move || loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(interval);
        if stop.load(Ordering::Acquire) {
            break;
        }
        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_millis();
        if elapsed_ms == 0 {
            continue;
        }
        let attempts = attempts_done.load(Ordering::Relaxed);
        let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
        let stats = ProgressStats {
            attempts,
            attempts_per_sec: attempts as f64 / elapsed_secs,
            elapsed_ms,
        };
        if json_mode {
            match serde_json::to_string(&stats) {
                Ok(line) => println!("STATS {line}"),
                Err(err) => eprintln!("Failed to serialize stats: {err:?}"),
            }
        } else {
            println!(
                "Stats | attempts={} | rate={:.2}/s | elapsed={:.2?}",
                stats.attempts, stats.attempts_per_sec, elapsed
            );
        }
    }))
}

fn load_checkpoint_file(path: &Path) -> Result<CheckpointFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Unable to read checkpoint {}", path.display()))?;
    let checkpoint: CheckpointFile = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid checkpoint JSON {}", path.display()))?;
    if checkpoint.version != 1 {
        return Err(anyhow!(
            "Unsupported checkpoint version {}",
            checkpoint.version
        ));
    }
    Ok(checkpoint)
}

fn save_checkpoint_file(path: &Path, payload: &CheckpointFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create checkpoint dir {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(payload)?;
    fs::write(path, data)
        .with_context(|| format!("Failed to write checkpoint {}", path.display()))?;
    Ok(())
}

fn append_result_file(path: &Path, report: &VanityResult) -> Result<()> {
    let mut entries: Vec<Value> = Vec::new();
    if path.exists() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read existing result file {}", path.display()))?;
        if !raw.trim().is_empty() {
            let existing: Value = serde_json::from_str(&raw).with_context(|| {
                format!("Failed to parse existing result file {}", path.display())
            })?;
            match existing {
                Value::Array(arr) => entries = arr,
                other => entries.push(other),
            }
        }
    }
    entries.push(serde_json::to_value(report)?);
    let data = serde_json::to_vec_pretty(&entries)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create result dir {}", parent.display()))?;
    }
    fs::write(path, data)
        .with_context(|| format!("Failed to write result file {}", path.display()))?;
    Ok(())
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
