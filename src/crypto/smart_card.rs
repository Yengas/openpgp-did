use std::error::Error;

use super::key::{Key, SigningKey};

#[derive(Debug)]
pub struct SmartCardInfo {
    pub card_info: String,
    pub keys: Vec<Key>,
    pub signing_counter: u32,
}

pub trait SmartCard {
    fn get_card_info(&mut self) -> Result<SmartCardInfo, Box<dyn Error>>;
    fn sign_data(&mut self, key: &SigningKey, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
}
