use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};

pub struct PoseidonTreeConfig;

impl Config for PoseidonTreeConfig {
    type Leaf = [u8; 32];
    type LeafDigest = ;
    type LeafInnerDigestConverter = ;
    type InnerDigest = ;
    type LeafHash =;
    type TwoToOneHash =;
}
