use digest::{Digest, Output};

pub struct TreeRoot<D: Digest> {
    root: Output<D>,
}

impl<D: Digest> TreeRoot<D> {
    pub fn commit(data: &[impl AsRef<[u8]>]) -> Output<D> {
        let size = data.len();
        assert!(
            size & (size - 1) == 0,
            "Size of data has to be a power of 2"
        ); // size has to be a power of 2
        let tree_depth = size.trailing_zeros(); // calculate the log2 of a power of 2

        let mut leafs: Vec<Output<D>> = data.iter().map(|x| D::digest(x)).collect();
        for tree_level in 0..tree_depth {
            let step_size = 2 << tree_level;
            let step_number = size / step_size;
            for j in 0..step_number {
                let left_index = j * step_size;
                let right_index = left_index + step_size / 2;
                let mut hash = D::new();
                hash.update(leafs[left_index].as_ref());
                hash.update(leafs[right_index].as_ref());
                leafs[left_index] = hash.finalize();
            }
        }

        leafs[0].clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_simple_root_commitment() {
        let msg = "hello world";
        let hash = Sha256::digest(msg);
        let result = hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(hash[..], result[..]);

        let mut hash_func = Sha256::new();
        hash_func.update(hash);
        hash_func.update(hash);
        let root_should = hash_func.finalize();
        let leafs = [msg, msg];
        let tree_root: Output<Sha256> = TreeRoot::<Sha256>::commit(&leafs);
        assert_eq!(tree_root[..], root_should[..]);
    }
}
