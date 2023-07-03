use reqwest::Client;
use sha1::{Digest, Sha1};
use std::{num::ParseIntError, str::FromStr};
use thiserror::Error;

#[derive(Clone, Debug, Default)]
pub struct Hibr {
    client: Client,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuffixMatch {
    suffix: String,
    count: u32,
}

impl ToString for SuffixMatch {
    fn to_string(&self) -> String {
        format!("{}:{}", self.suffix, self.count)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuffixMatches {
    matches: Vec<SuffixMatch>,
}

impl ToString for SuffixMatches {
    fn to_string(&self) -> String {
        self.matches
            .iter()
            .map(|m| format!("{}\n", m.to_string()))
            .collect()
    }
}

/// Errors that can occur when parsing hash suffix response
#[derive(Error, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ParseSuffixMatchError {
    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),
    #[error("String is not in correct suffix:count format `{0}`")]
    InvalidFormat(String),
}

/// Errors that can occur when parsing hash suffix response
#[derive(Error, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HibrError {
    #[error(transparent)]
    ParseSuffixMatchError(#[from] ParseSuffixMatchError),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
}

impl FromStr for SuffixMatches {
    type Err = ParseSuffixMatchError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result: Vec<SuffixMatch> = Vec::new();
        for line in s
            .lines()
            .into_iter()
            .filter(|s| !s.is_empty() && !s.as_bytes().iter().all(u8::is_ascii_whitespace))
            .map(str::trim)
        {
            let (hash_suffix, count) = line
                .split_once(':')
                .ok_or(ParseSuffixMatchError::InvalidFormat(String::from(line)))?;
            let suffix_match = SuffixMatch {
                suffix: hash_suffix.to_string(),
                count: count.parse()?,
            };

            result.push(suffix_match);
        }
        Ok(SuffixMatches { matches: result })
    }
}

impl Hibr {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::default(),
        }
    }

    fn get_hash(password: &str) -> String {
        let hash = Sha1::digest(password.as_bytes());
        base16ct::upper::encode_string(&hash)
    }

    pub async fn pw_range_search(&self, hash_prefix: &str) -> Result<SuffixMatches, HibrError> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", hash_prefix);

        let resp = self.client.get(&url).send().await?;
        let body = resp.text().await?;

        Ok(body.parse()?)
    }

    pub async fn get_password_count(&self, password: &str) -> Result<u32, HibrError> {
        let hex_hash = Self::get_hash(password);

        let hash_prefix = &hex_hash[0..5];
        let hash_suffix = &hex_hash[5..];

        let suffix_matches = self.pw_range_search(hash_prefix).await?;

        for hash_match in suffix_matches.matches {
            if hash_match.suffix == hash_suffix {
                return Ok(hash_match.count);
            }
        }

        Ok(0)
    }

    pub async fn is_password_breached(&self, password: &str) -> Result<bool, HibrError> {
        let count = self.get_password_count(password).await?;
        Ok(count > 0)
    }
}

/*
00188FF7A742810CC2982D0379EEBCF180C:6
003D48AD15D701272145597291E53FF3679:7
009EA61D69788288AB750E60F98C276152B:4
00F9060F5931C1C6300299841CE492AC2A3:5
0102143CAE940C8ACBAF8EB34A781CAC213:9
0147EDA4CFE3858796320DF925273B78156:1
017EE59C456A073F0D8732EBA9BC968D49F:1
01914DBE12B6E393B3C1A4C1CFB81D42308:1
021F1BE5DE3276F48A3836B742749CAF00C:1
029525FF478DE4CE4396803B32881E6BDB2:20
02FDA64710B70F9999A5B19D329F8F87BCE:4
03B550362E821C84A008F83F8B96FE5579E:3
03DB919530C802CA60C37E505B0543E20C3:10
046F4B02D3C999C9841BF5AFA6FC14C4150:1
04F1EAB6A395B2E480C809A02B061048056:2
04F3FEEA8A26051C3EEBE996BA03DC5E3FD:4
052AC7FA8ACB3A772D9176986C882F01982:1
056C26779E439CEAB8B74B0BB3D29564CE2:4
0572DF5B7481D8DA0BF14B030B9398EC25E:3
0601489B9845EFC4B8D8A8C22C03C44320E:4
06206E6570B32E31C14C65A3C5918C755C5:1
06ADF8619B2A1C92B442A55F06EA1CE6BBE:1
06B120F575E9DDA9F774BA1657594C6FFB9:3
06C04F6B5DD6364D71F822981A2DFEBBF16:7
06CD1B07C1234649F6CB42596FD00045E61:1
072FA38A4987A0B51480119FE4134DCD24D:8
076A03B624D6EAFBE088677454BF639221E:2
 */

#[cfg(test)]
mod tests {
    use crate::SuffixMatches;

    #[test]
    fn parse_suffix_match() {
        let input = "00188FF7A742810CC2982D0379EEBCF180C:6
         003D48AD15D701272145597291E53FF3679:7
         009EA61D69788288AB750E60F98C276152B:4
         00F9060F5931C1C6300299841CE492AC2A3:5
         ";

        let result: SuffixMatches = input.parse().unwrap();
        assert_eq!(
            result.matches[0].suffix,
            "00188FF7A742810CC2982D0379EEBCF180C"
        );
        assert_eq!(result.matches[0].count, 6);

        assert_eq!(
            result.matches[1].suffix,
            "003D48AD15D701272145597291E53FF3679"
        );
        assert_eq!(result.matches[1].count, 7);

        assert_eq!(
            result.matches[2].suffix,
            "009EA61D69788288AB750E60F98C276152B"
        );
        assert_eq!(result.matches[2].count, 4);
    }
}
