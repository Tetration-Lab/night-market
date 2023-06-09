//! Sparse Merkle Tree implementation.
//!
//! Modified from [Webb tools](https://github.com/webb-tools/zero-knowledge-gadgets) to support
//! generic hashers from `Arkworks` [TwoToOneCRH] and [TwoToOneCRHGadget] traits.

use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use thiserror::Error as ThisError;

/// Error enum for Sparse Merkle Tree.
#[derive(ThisError, Debug)]
pub enum MerkleError {
    /// Thrown when the given leaf is not in the tree or the path.
    #[error("Invalid leaf")]
    InvalidLeaf,

    /// Thrown when the merkle path is invalid.
    #[error("Path nodes are not consistent")]
    InvalidPathNodes,

    #[error("Io: {0}")]
    Io(String),

    #[error("Std: {0}")]
    Std(String),
}

impl From<ark_std::io::Error> for MerkleError {
    fn from(e: ark_std::io::Error) -> Self {
        MerkleError::Io(e.to_string())
    }
}

impl From<Box<dyn ark_std::error::Error>> for MerkleError {
    fn from(e: Box<dyn ark_std::error::Error>) -> Self {
        MerkleError::Std(e.to_string())
    }
}

/// The Path struct.
///
/// The path contains a sequence of sibling nodes that make up a merkle proof.
/// Each pair is used to identify whether an incremental merkle root
/// construction is valid at each intermediate step.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Path<F: PrimeField, H: TwoToOneCRHScheme<Input = F, Output = F>, const N: usize> {
    /// The path represented as a sequence of sibling pairs.
    pub path: [(F, F); N],
    /// The phantom hasher type used to reconstruct the merkle root.
    pub marker: PhantomData<H>,
}

impl<F: PrimeField, H: TwoToOneCRHScheme<Input = F, Output = F>, const N: usize> Path<F, H, N> {
    /// Creates a new empty path.
    pub fn empty() -> Self {
        Self {
            path: [(F::zero(), F::zero()); N],
            marker: PhantomData,
        }
    }

    /// Takes in an expected `root_hash` and leaf-level data (i.e. hashes of
    /// secrets) for a leaf and checks that the leaf belongs to a tree having
    /// the expected hash.
    pub fn check_membership(
        &self,
        root_hash: &F,
        leaf: &F,
        hasher: &H::Parameters,
    ) -> Result<bool, MerkleError> {
        let root = self.calculate_root(leaf, hasher)?;
        Ok(root == *root_hash)
    }

    /// Assumes leaf contains leaf-level data, i.e. hashes of secrets
    /// stored on leaf-level.
    pub fn calculate_root(&self, leaf: &F, hasher: &H::Parameters) -> Result<F, MerkleError> {
        if *leaf != self.path[0].0 && *leaf != self.path[0].1 {
            return Err(MerkleError::InvalidLeaf);
        }

        let mut prev = *leaf;
        // Check levels between leaf level and root
        for (left_hash, right_hash) in &self.path {
            if &prev != left_hash && &prev != right_hash {
                return Err(MerkleError::InvalidPathNodes);
            }
            prev = <H as TwoToOneCRHScheme>::evaluate(hasher, left_hash, right_hash)?;
        }

        Ok(prev)
    }

    /// Given leaf data determine what the index of this leaf must be
    /// in the Merkle tree it belongs to.  Before doing so check that the leaf
    /// does indeed belong to a tree with the given `root_hash`
    pub fn get_index(
        &self,
        root_hash: &F,
        leaf: &F,
        hasher: &H::Parameters,
    ) -> Result<F, MerkleError> {
        if !self.check_membership(root_hash, leaf, hasher)? {
            return Err(MerkleError::InvalidLeaf);
        }

        let mut prev = *leaf;
        let mut index = F::zero();
        let mut twopower = F::one();
        // Check levels between leaf level and root
        for (left_hash, right_hash) in &self.path {
            // Check if the previous hash is for a left node or right node
            if &prev != left_hash {
                index += twopower;
            }
            twopower = twopower + twopower;
            prev = <H as TwoToOneCRHScheme>::evaluate(hasher, left_hash, right_hash)?;
        }

        Ok(index)
    }
}

/// The Sparse Merkle Tree struct.
///
/// The Sparse Merkle Tree stores a set of leaves represented in a map and
/// a set of empty hashes that it uses to represent the sparse areas of the
/// tree.
#[derive(Debug, Clone, PartialEq)]
pub struct SparseMerkleTree<
    F: PrimeField,
    H: TwoToOneCRHScheme<Input = F, Output = F>,
    const N: usize,
> {
    /// A map from leaf indices to leaf data stored as field elements.
    pub tree: BTreeMap<u64, F>,
    /// An array of default hashes hashed with themselves `N` times.
    empty_hashes: [F; N],
    /// The phantom hasher type used to build the merkle tree.
    marker: PhantomData<H>,
}

impl<F: PrimeField, H: TwoToOneCRHScheme<Input = F, Output = F>, const N: usize>
    SparseMerkleTree<F, H, N>
{
    /// Takes a batch of field elements, inserts
    /// these hashes into the tree, and updates the merkle root.
    pub fn insert_batch(
        &mut self,
        leaves: &BTreeMap<u32, F>,
        hasher: &H::Parameters,
    ) -> Result<(), MerkleError> {
        let last_level_index: u64 = (1u64 << N) - 1;

        let mut level_idxs: BTreeSet<u64> = BTreeSet::new();
        for (i, leaf) in leaves {
            let true_index = last_level_index + (*i as u64);
            self.tree.insert(true_index, *leaf);
            level_idxs.insert((true_index - 1) >> 1);
        }

        for level in 0..N {
            let mut new_idxs: BTreeSet<u64> = BTreeSet::new();
            for i in level_idxs {
                let left_index = 2 * i + 1;
                let right_index = 2 * i + 2;

                let empty_hash = self.empty_hashes[level];
                let left = self.tree.get(&left_index).unwrap_or(&empty_hash);
                let right = self.tree.get(&right_index).unwrap_or(&empty_hash);
                let hashed = <H as TwoToOneCRHScheme>::evaluate(hasher, left, right)?;
                self.tree.insert(i, hashed);

                let parent = match i > 0 {
                    true => (i - 1) >> 1,
                    false => break,
                };
                new_idxs.insert(parent);
            }
            level_idxs = new_idxs;
        }

        Ok(())
    }

    /// Creates a new Sparse Merkle Tree from a map of indices to field
    /// elements.
    pub fn new(
        leaves: &BTreeMap<u32, F>,
        hasher: &H::Parameters,
        empty_leaf: &F,
    ) -> Result<Self, MerkleError> {
        // Ensure the tree can hold this many leaves
        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_height = ark_std::log2(tree_size);
        assert!(tree_height <= N as u32);

        // Initialize the merkle tree
        let tree: BTreeMap<u64, F> = BTreeMap::new();
        let empty_hashes = {
            let mut empty_hashes = [<F>::zero(); N];

            let mut empty_hash = *empty_leaf;
            empty_hashes[0] = empty_hash;

            for hash in empty_hashes.iter_mut().skip(1) {
                empty_hash = <H as TwoToOneCRHScheme>::evaluate(hasher, &empty_hash, &empty_hash)?;
                *hash = empty_hash;
            }

            Result::<_, MerkleError>::Ok(empty_hashes)
        }?;

        let mut smt = SparseMerkleTree::<F, H, N> {
            tree,
            empty_hashes,
            marker: PhantomData,
        };
        smt.insert_batch(leaves, hasher)?;

        Ok(smt)
    }

    /// Creates a new Sparse Merkle Tree from an array of field elements.
    pub fn new_sequential(
        leaves: &[F],
        hasher: &H::Parameters,
        empty_leaf: &F,
    ) -> Result<Self, MerkleError> {
        let pairs: BTreeMap<u32, F> = leaves
            .iter()
            .enumerate()
            .map(|(i, l)| (i as u32, *l))
            .collect();
        let smt = Self::new(&pairs, hasher, empty_leaf)?;

        Ok(smt)
    }

    /// Returns the Merkle tree root.
    pub fn root(&self) -> F {
        self.tree
            .get(&0)
            .cloned()
            .unwrap_or(*self.empty_hashes.last().unwrap())
    }

    /// Give the path leading from the leaf at `index` up to the root.  This is
    /// a "proof" in the sense of "valid path in a Merkle tree", not a ZK
    /// argument.
    pub fn generate_membership_proof(&self, index: u64) -> Path<F, H, N> {
        let mut path = [(F::zero(), F::zero()); N];

        let tree_index = index + (1u64 << N) - 1;

        // Iterate from the leaf up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        let mut level = 0;
        while current_node != 0 {
            let sibling_node = if current_node % 2 == 1 {
                current_node + 1
            } else {
                current_node - 1
            };

            let empty_hash = &self.empty_hashes[level];

            let current = self.tree.get(&current_node).cloned().unwrap_or(*empty_hash);
            let sibling = self.tree.get(&sibling_node).cloned().unwrap_or(*empty_hash);

            if current_node % 2 == 1 {
                path[level] = (current, sibling);
            } else {
                path[level] = (sibling, current);
            }
            current_node = (current_node - 1) >> 1;
            level += 1;
        }

        Path {
            path,
            marker: PhantomData,
        }
    }
}

/// Gadgets for one Merkle tree path
#[derive(Debug, Clone)]
pub struct PathVar<
    F: PrimeField,
    H: TwoToOneCRHScheme<Input = F, Output = F>,
    HG: TwoToOneCRHSchemeGadget<H, F, InputVar = FpVar<F>, OutputVar = FpVar<F>>,
    const N: usize,
> {
    path: [(FpVar<F>, FpVar<F>); N],
    _phantom: (PhantomData<H>, PhantomData<HG>),
}

impl<
        F: PrimeField,
        H: TwoToOneCRHScheme<Input = F, Output = F>,
        HG: TwoToOneCRHSchemeGadget<H, F, InputVar = FpVar<F>, OutputVar = FpVar<F>>,
        const N: usize,
    > PathVar<F, H, HG, N>
{
    /// check whether path belongs to merkle path (does not check if indexes
    /// match)
    pub fn check_membership(
        &self,
        root: &FpVar<F>,
        leaf: &FpVar<F>,
        hasher: &HG::ParametersVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        let computed_root = self.root_hash(leaf, hasher)?;

        root.is_eq(&computed_root)
    }

    /// Creates circuit to calculate merkle root and deny any invalid paths
    pub fn root_hash(
        &self,
        leaf: &FpVar<F>,
        hasher: &HG::ParametersVar,
    ) -> Result<FpVar<F>, SynthesisError> {
        assert_eq!(self.path.len(), N);
        let mut previous_hash = leaf.clone();

        for (p_left_hash, p_right_hash) in self.path.iter() {
            let previous_is_left = previous_hash.is_eq(p_left_hash)?;

            let left_hash =
                FpVar::conditionally_select(&previous_is_left, &previous_hash, p_left_hash)?;
            let right_hash =
                FpVar::conditionally_select(&previous_is_left, p_right_hash, &previous_hash)?;

            previous_hash =
                <HG as TwoToOneCRHSchemeGadget<H, F>>::evaluate(hasher, &left_hash, &right_hash)?;
        }

        Ok(previous_hash)
    }

    /// Creates circuit to get index of a leaf hash
    pub fn get_index(
        &self,
        leaf: &FpVar<F>,
        hasher: &HG::ParametersVar,
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut index = FpVar::<F>::zero();
        let mut twopower = FpVar::<F>::one();
        let mut rightvalue: FpVar<F>;

        // Check levels between leaf level and root.
        let mut previous_hash = leaf.clone();
        for (left_hash, right_hash) in self.path.iter() {
            // Check if the previous_hash is for a left node.
            let previous_is_left = previous_hash.is_eq(left_hash)?;

            rightvalue = &index + &twopower;
            index = FpVar::<F>::conditionally_select(&previous_is_left, &index, &rightvalue)?;
            twopower = &twopower + &twopower;

            previous_hash =
                <HG as TwoToOneCRHSchemeGadget<H, F>>::evaluate(hasher, &left_hash, &right_hash)?;
        }

        Ok(index)
    }
}

impl<
        F: PrimeField,
        H: TwoToOneCRHScheme<Input = F, Output = F>,
        HG: TwoToOneCRHSchemeGadget<H, F, InputVar = FpVar<F>, OutputVar = FpVar<F>>,
        const N: usize,
    > AllocVar<Path<F, H, N>, F> for PathVar<F, H, HG, N>
{
    fn new_variable<T: Borrow<Path<F, H, N>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut path = Vec::new();
        let path_obj = f()?;
        for (l, r) in &path_obj.borrow().path {
            let l_hash =
                FpVar::<F>::new_variable(ark_relations::ns!(cs, "l_child"), || Ok(*l), mode)?;
            let r_hash =
                FpVar::<F>::new_variable(ark_relations::ns!(cs, "r_child"), || Ok(*r), mode)?;
            path.push((l_hash, r_hash));
        }

        Ok(PathVar {
            path: path.try_into().unwrap_or_else(
                #[allow(clippy::type_complexity)]
                |v: Vec<(FpVar<F>, FpVar<F>)>| {
                    panic!("Expected a Vec of length {} but it was {}", N, v.len())
                },
            ),
            _phantom: (PhantomData, PhantomData),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error};

    use ark_bn254::Fr;
    use ark_std::Zero;

    use crate::{poseidon::PoseidonHash, utils::poseidon_bn254, TREE_DEPTH};

    use super::SparseMerkleTree;

    #[test]
    fn correct_proof() -> Result<(), Box<dyn Error>> {
        let hash = poseidon_bn254();
        let mut tree = SparseMerkleTree::<Fr, PoseidonHash<Fr>, TREE_DEPTH>::new(
            &BTreeMap::new(),
            &hash,
            &Fr::zero(),
        )
        .expect("should create empty tree");

        tree.insert_batch(&BTreeMap::from([(0, Fr::from(1))]), &hash)?;
        tree.insert_batch(&BTreeMap::from([(1, Fr::from(10))]), &hash)?;

        let proof = tree.generate_membership_proof(1);

        let root = proof.calculate_root(&Fr::from(10), &hash)?;

        assert_eq!(root, tree.root());

        Ok(())
    }
}
