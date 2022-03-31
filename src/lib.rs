#[macro_use]
extern crate lazy_static;

use regex::Regex;
use reqwest::Client;
use sha1::{digest::core_api::CoreWrapper, Digest, Sha1, Sha1Core};
use std::sync::Mutex;

lazy_static! {
    static ref PW_RESPONSE_MATCH: Regex = Regex::new(r"([0-9a-fA-F]+):([0-9]+)").unwrap();
    static ref SHA1: Mutex<CoreWrapper<Sha1Core>> = Mutex::new(Sha1::new());
}

pub async fn pw_range_search(client: &Client, hash_prefix: &str) -> reqwest::Result<String> {
    let url = format!("https://api.pwnedpasswords.com/range/{}", hash_prefix);

    let resp = client.get(&url).send().await?;
    let body = resp.text().await?;

    Ok(body)
}

pub async fn get_password_count(client: &Client, password: &str) -> reqwest::Result<u32> {
    let mut hasher = SHA1.lock().unwrap();
    hasher.update(password);
    let result = hasher.finalize_reset();
    let hex_hash = base16ct::upper::encode_string(&result);

    let hash_prefix = &hex_hash[0..5];
    let hash_suffix = &hex_hash[5..];

    let resp = pw_range_search(client, hash_prefix).await?;

    for m in PW_RESPONSE_MATCH.captures_iter(&resp) {
        if m[1] == *hash_suffix {
            return Ok(m[2].parse().unwrap());
        }
    }

    Ok(0)
}
