use regex::Regex;
use reqwest::Client;
use sha1::{Digest, Sha1};

pub struct Hibr {
    client: Client,
    pw_response_match: Regex,
}

impl Hibr {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            pw_response_match: Regex::new(r"([0-9a-fA-F]+):([0-9]+)").unwrap(),
        }
    }

    fn get_hash(password: &str) -> String {
        let hash = Sha1::digest(password.as_bytes());
        base16ct::upper::encode_string(&hash)
    }

    pub async fn get_password_count(&self, password: &str) -> reqwest::Result<u32> {
        let hex_hash = Hibr::get_hash(password);

        let hash_prefix = &hex_hash[0..5];
        let hash_suffix = &hex_hash[5..];

        let resp = self.pw_range_search(hash_prefix).await?;

        for m in self.pw_response_match.captures_iter(&resp) {
            if m[1] == *hash_suffix {
                return Ok(m[2].parse().unwrap());
            }
        }

        Ok(0)
    }

    pub async fn is_password_breached(&self, password: &str) -> reqwest::Result<bool> {
        let count = self.get_password_count(password).await?;
        Ok(count > 0)
    }

    pub async fn pw_range_search(&self, hash_prefix: &str) -> reqwest::Result<String> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", hash_prefix);

        let resp = self.client.get(&url).send().await?;
        let body = resp.text().await?;

        Ok(body)
    }
}
