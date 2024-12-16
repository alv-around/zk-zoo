use claim::assert_ok;
use p3_baby_bear::BabyBear;
use p3_blake3::Blake3;
use p3_commit::Mmcs;
use p3_field::AbstractField;
use p3_matrix::Dimensions;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};

type F = BabyBear;
type H = SerializingHasher32<Blake3>;
type C = CompressionFunctionFromHasher<u8, Blake3, 2, 32>;
type Blake3MerkleTree<'a> = FieldMerkleTreeMmcs<F, u8, H, C, 32>;

fn main() {
    let b = Blake3 {};
    let hash = H::new(b);
    let compress = C::new(b);

    let data: Vec<F> = vec![
        F::from_canonical_u32(1),
        F::from_canonical_u32(2),
        F::from_canonical_u32(3),
        F::from_canonical_u32(4),
    ];
    let tree = Blake3MerkleTree::new(hash, compress);
    let (commit, prover_data) = tree.commit_vec(data);
    println!("Commit: {:?}", commit);
    println!("Tree: {:?}", prover_data);

    let index = 2;
    let (opened_value, proof) = tree.open_batch(index, &prover_data);
    let height = tree.get_max_height(&prover_data);
    let dims = Dimensions { height, width: 1 };
    println!("Proof: {:?}", &proof);

    assert_ok!(tree.verify_batch(&commit, &[dims], index, &opened_value, &proof));
}
