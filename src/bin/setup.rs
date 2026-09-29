//! One-time configuration. Turns your two secret codes into `web/pairing.bin`.
//!
//! Native only — it reads a terminal, which a browser has no equivalent of.
//! The web build uses `--lib`, so this target is never part of the artifact.
//!
//! The codes themselves never leave this machine and are never written to disk.
//! What gets written — and later committed and published — is one random
//! pairing secret wrapped twice under Argon2id, which is useless without a
//! code. Run this before the first deploy, and again any time you want to
//! change the codes.

use princess_roll::crypto::{normalize_code, random, ARGON2_M_KIB, ARGON2_T_COST};
use princess_roll::pairing::Pairing;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

/// Crockford's base32 alphabet: no I, L, O or U, so nothing is mistaken for
/// something else when read aloud or copied by hand.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUPS: usize = 5;
const GROUP_LEN: usize = 5;

/// Short codes are the one weak point in this design: the wrapped file is
/// public and can be attacked offline forever. Argon2id makes each guess
/// expensive, but it cannot rescue a four-character code.
const MIN_CODE_LEN: usize = 12;
const COMFORTABLE_CODE_LEN: usize = 20;

fn output_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("web/pairing.bin")
}

/// 25 characters drawn uniformly from a 32-symbol alphabet: 125 bits.
fn generate_code() -> String {
    let bytes: [u8; GROUPS * GROUP_LEN] = random();
    bytes
        .chunks(GROUP_LEN)
        .map(|group| {
            group
                .iter()
                .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn prompt_line(question: &str) -> io::Result<String> {
    print!("{question}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().to_string())
}

fn prompt_yes_no(question: &str, default_yes: bool) -> io::Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        match prompt_line(&format!("{question} {hint} "))?.to_lowercase().as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("  Please answer y or n."),
        }
    }
}

/// Read a code without echoing it, and confirm it, so a typo cannot silently
/// lock someone out of a file they are about to publish.
fn prompt_code(role: &str) -> io::Result<String> {
    loop {
        let first = rpassword::prompt_password(format!("  {role}'s code (not shown): "))?;
        let normalized = normalize_code(&first);

        if normalized.len() < MIN_CODE_LEN {
            println!(
                "  Too short — {MIN_CODE_LEN} characters minimum, and this file is \
                 publicly downloadable once deployed. Try again."
            );
            continue;
        }
        if normalized.len() < COMFORTABLE_CODE_LEN {
            println!(
                "  Accepted, but {} characters is on the short side for something \
                 an attacker can grind offline.",
                normalized.len()
            );
        }

        let again = rpassword::prompt_password(format!("  {role}'s code again: "))?;
        if normalize_code(&again) != normalized {
            println!("  Those did not match. Try again.");
            continue;
        }
        return Ok(normalized);
    }
}

fn main() -> io::Result<()> {
    println!("\nPrincess-Roll setup");
    println!("===================\n");
    println!("This writes one file: web/pairing.bin");
    println!("It holds a random pairing secret wrapped under each of your two codes.");
    println!("Your codes are never stored, never printed back, and never leave this machine.\n");

    if !io::stdin().is_terminal() {
        eprintln!("This needs an interactive terminal — run it directly, not through a pipe.");
        std::process::exit(1);
    }

    let destination = output_path();
    if destination.exists() {
        println!("web/pairing.bin already exists.");
        println!("Replacing it invalidates the current codes: anyone mid-session stays");
        println!("connected, but nobody can start a new one with the old codes.\n");
        if !prompt_yes_no("Replace it?", false)? {
            println!("\nLeft untouched. Nothing was changed.");
            return Ok(());
        }
        println!();
    }

    let generate = prompt_yes_no("Generate two strong codes for you?", true)?;
    println!();

    let (daddy_code, princess_code) = if generate {
        let daddy = generate_code();
        let princess = generate_code();

        println!("Store these in a password manager now. They are shown once and");
        println!("cannot be recovered from the file — if you lose them, re-run setup.\n");
        println!("  Daddy    {daddy}");
        println!("  Princess {princess}\n");

        if !prompt_yes_no("Saved both?", false)? {
            println!("\nNothing was written. Run setup again when you are ready.");
            return Ok(());
        }
        (daddy, princess)
    } else {
        println!("Type each code twice. Nothing is echoed.\n");
        let daddy = prompt_code("Daddy")?;
        let princess = prompt_code("Princess")?;
        (daddy, princess)
    };

    if daddy_code == princess_code {
        eprintln!("\nThe two codes must differ — they are what tells the page which role");
        eprintln!("you are. Nothing was written.");
        std::process::exit(1);
    }

    println!("\nDeriving keys (Argon2id, {} MiB, {ARGON2_T_COST} passes — this is meant to be slow)...", ARGON2_M_KIB / 1024);

    let (pairing, _secret) = Pairing::create(&daddy_code, &princess_code)
        .map_err(|e| io::Error::other(format!("could not build the pairing file: {e}")))?;

    // Round-trip both codes before writing, so a corrupt file is never the
    // thing you discover at the moment you want to use it.
    let encoded = pairing.encode();
    let check = Pairing::decode(&encoded)
        .map_err(|e| io::Error::other(format!("self-check failed to parse: {e}")))?;
    for (label, code) in [("Daddy", &daddy_code), ("Princess", &princess_code)] {
        if check.unlock(code).is_none() {
            return Err(io::Error::other(format!(
                "self-check failed: {label}'s code did not unlock the file it was just written into"
            )));
        }
    }

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&destination, &encoded)?;

    println!("\nWrote {} ({} bytes).\n", destination.display(), encoded.len());
    println!("Both codes verified against the file. Next:");
    println!("  ./build.sh          build the page into docs/");
    println!("  ./serve.sh          open it locally at http://localhost:8080");
    println!("  git add web/pairing.bin && git commit && git push");
    println!("\nThe file is ciphertext, so committing it to a public repo is safe.");
    println!("Your codes are what must stay private.\n");

    Ok(())
}
