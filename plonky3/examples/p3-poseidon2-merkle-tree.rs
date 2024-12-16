use claim::assert_ok;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_commit::Mmcs;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Dimensions};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::thread_rng;

type F = BabyBear;
type Perm = Poseidon2<F, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>; // WIDTH
                                                                                          // = 16 => t; alpha = 8 => D
type H = PaddingFreeSponge<Perm, 16, 8, 8>;
type C = TruncatedPermutation<Perm, 2, 8, 16>;
type Poseidon2MerkleTree =
    FieldMerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, H, C, 8>;

fn main() {
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear::default(),
        &mut thread_rng(),
    );
    let hash = H::new(perm.clone());
    let compress = C::new(perm);

    const ROWS: usize = 1 << 8;
    const COLS: usize = 2;
    let matrix = RowMajorMatrix::<F>::rand(&mut thread_rng(), ROWS, COLS);
    let leafs = vec![matrix];

    let tree = Poseidon2MerkleTree::new(hash, compress);
    let (commit, prover_data) = tree.commit(leafs);
    println!("Commit: {:?}", commit);
    println!("Tree: {:?}", prover_data);

    let index = 2;
    let (opened_value, proof) = tree.open_batch(index, &prover_data);
    let height = tree.get_max_height(&prover_data);
    let dims = Dimensions { height, width: 1 };
    println!("Proof: {:?}", &proof);

    assert_ok!(tree.verify_batch(&commit, &[dims], index, &opened_value, &proof));
}
