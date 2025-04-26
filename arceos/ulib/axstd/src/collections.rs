extern crate alloc;
use alloc::{vec::Vec, string::String};

use arceos_api::modules::axhal::misc::random;

fn hash_key(key: &str) -> usize {
    let mut hash = 0u128;
    for b in key.as_bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(*b as u128);
    }
    let salt = random();
    (hash ^ salt) as usize
}

pub struct HashMap {
    buckets: Vec<Vec<(String, u32)>>,
}

impl HashMap {
    pub fn new() -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(Vec::new());
        }
        Self { buckets }
    }

    pub fn insert(&mut self, key: String, value: u32) {
        let hash = hash_key(&key) % self.buckets.len();
        for entry in self.buckets[hash].iter_mut() {
            if entry.0 == key {
                entry.1 = value;
                return;
            }
        }
        self.buckets[hash].push((key, value));
    }

    pub fn get(&self, key: &str) -> Option<u32> {
        let hash = hash_key(key) % self.buckets.len();
        self.buckets[hash]
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, u32)> {
        self.buckets.iter().flat_map(|bucket| bucket.iter())
    }
}
