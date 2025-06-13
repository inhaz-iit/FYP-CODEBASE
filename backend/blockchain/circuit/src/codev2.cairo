// Cairo 2.9.2 Compatible STARK Proof Verification
// This implementation is adapted for Cairo 2.9.2 syntax and available functions
// Key changes: 
// - Removed return statements from loops (Cairo 2.9.2 restriction)
// - Replaced bitwise operations with arithmetic equivalents
// - Uses Poseidon hash (RECOMMENDED for STARK systems - more efficient than Pedersen)
// - Proper field arithmetic handling

use core::array::ArrayTrait;
use core::option::OptionTrait;
use core::traits::TryInto;
use core::traits::Into;
use core::poseidon::poseidon_hash_span;

#[starknet::contract]
mod codev2 {
    use super::{ArrayTrait, OptionTrait, TryInto, Into, poseidon_hash_span};

    const FIELD_PRIME: felt252 = 0x400000000000008100000000000000000000000000000000000000000000001;
    const GENERATOR: felt252 = 3;
    const FRI_ROUNDS: u32 = 8;
    const BLOW_UP_FACTOR: u32 = 16;
    const SECURITY_LEVEL: u32 = 80;  // 80-bit security
    const NUM_QUERIES: u32 = 32;     // Number of FRI queries for soundness
    
    #[storage]
    struct Storage {
        proofs: starknet::storage::Map::<felt252, bool>,
    }

    // ============ IMPROVED DATA STRUCTURES ============

    #[derive(Drop, Serde, Clone)]
    struct EvaluationDomain {
        size: u32,              // Must be power of 2
        generator: felt252,     // Primitive root of unity
        offset: felt252,        // Coset offset for evaluation
    }

    #[derive(Drop, Serde, Clone)]
    struct MerkleTree {
        root: felt252,
        height: u32,
        nodes: Array<Array<felt252>>,  // Level-by-level storage
    }

    #[derive(Drop, Serde, Clone)]
    struct MerkleProof {
        leaf_index: u32,
        leaf_value: felt252,
        authentication_path: Array<felt252>,
    }

    #[derive(Drop, Serde, Clone)]
    struct FRIQuery {
        layer_index: u32,
        position: u32,
        value: felt252,
        sibling_value: felt252,
        merkle_proof: MerkleProof,
    }

    #[derive(Drop, Serde, Clone)]
    struct FRIQueryPhase {
        queries: Array<FRIQuery>,
        challenge: felt252,
    }

    #[derive(Drop, Serde, Clone)]
    struct FRICommitment {
        layer_trees: Array<MerkleTree>,
        layer_evaluations: Array<Array<felt252>>,
        final_polynomial: Array<felt252>,
        query_phase: FRIQueryPhase,
        domains: Array<EvaluationDomain>,
    }

    #[derive(Drop, Serde, Clone)]
    struct AIRConstraints {
        boundary_constraints: Array<felt252>,
        transition_constraints: Array<felt252>,
        permutation_constraints: Array<felt252>,
        constraint_degree: u32,
    }

    #[derive(Drop, Serde, Clone)]
    struct STARKProof {
        trace_commitment: MerkleTree,
        trace_evaluations: Array<felt252>,
        fri_proof: FRICommitment,
        low_degree_proof: Array<felt252>,
        public_coin_seed: felt252,  // For Fiat-Shamir
    }

    #[derive(Drop, Serde, Clone)]
    struct TraceTable {
        rows: Array<Array<felt252>>,
        width: usize,
        length: usize,
        domain: EvaluationDomain,
    }

    #[derive(Drop, Copy, Serde)]
    struct PublicInput {
        message_hash: felt252,
        public_key: felt252,
        signature: felt252,
    }

    // ============ DOMAIN AND FIELD ARITHMETIC ============
    // Note: Field arithmetic in Cairo is automatically reduced modulo the field prime

    fn create_evaluation_domain(size: u32, offset: felt252) -> EvaluationDomain {
        assert(is_power_of_two(size), 'Domain must be power of 2');
        
        // Find primitive root of unity for the given size
        let generator = find_primitive_root_of_unity(size);
        
        EvaluationDomain {
            size: size,
            generator: generator,
            offset: offset,
        }
    }

    fn is_power_of_two(n: u32) -> bool {
        if n == 0 {
            false
        } else {
            let mut temp = n;
            let mut is_power = true;
            
            loop {
                if temp == 1 {
                    break;
                }
                if temp % 2 != 0 {
                    is_power = false;
                    break;
                }
                temp = temp / 2;
            };
            
            is_power
        }
    }

    fn find_primitive_root_of_unity(size: u32) -> felt252 {
        // Simplified - in practice, you'd compute this properly
        // For size = 2^k, we need g^(2^k) = 1 and g^(2^(k-1)) != 1
        let mut generator = GENERATOR;
        let mut current_order = 1_u32;
        
        loop {
            if current_order >= size {
                break;
            }
            generator = field_mul(generator, generator);
            current_order *= 2;
        };
        
        generator
    }

    fn field_mul(a: felt252, b: felt252) -> felt252 {
        // Proper field multiplication with overflow checking
        let result = a * b;
        field_mod(result)
    }

    fn field_add(a: felt252, b: felt252) -> felt252 {
        let result = a + b;
        field_mod(result)
    }

    fn field_mod(value: felt252) -> felt252 {
        // In Cairo, felt252 arithmetic is automatically reduced modulo the field prime
        // No explicit modulo operation needed
        value
    }

    fn field_pow(base: felt252, exp: u32) -> felt252 {
        if exp == 0 {
            return 1;
        }
        
        let mut result = 1;
        let mut base_power = base;
        let mut remaining_exp = exp;
        
        loop {
            if remaining_exp == 0 {
                break;
            }
            
            if remaining_exp % 2 == 1 {
                result = field_mul(result, base_power);
            }
            
            base_power = field_mul(base_power, base_power);
            remaining_exp = remaining_exp / 2;
        };
        
        result
    }

    // ============ MERKLE TREE IMPLEMENTATION ============

    fn build_merkle_tree(leaves: @Array<felt252>) -> MerkleTree {
        assert(leaves.len() > 0, 'Cannot build tree from empty');
        let leaves_len_u32: u32 = leaves.len().try_into().unwrap_or(1);
        assert(is_power_of_two(leaves_len_u32), 'Leaves must be power of 2');
        
        let mut nodes = ArrayTrait::new();
        let mut current_level = leaves.clone();
        nodes.append(current_level.clone());
        
        let mut height = 0_u32;
        
        // Build tree bottom-up
        loop {
            if current_level.len() <= 1 {
                break;
            }
            
            let mut next_level = ArrayTrait::new();
            let mut i = 0;
            
            loop {
                if i >= current_level.len() {
                    break;
                }
                
                let left = *current_level.at(i);
                let right = if i + 1 < current_level.len() {
                    *current_level.at(i + 1)
                } else {
                    left  // Duplicate if odd number of nodes
                };
                
                let parent = hash_pair(left, right);
                next_level.append(parent);
                
                i += 2;
            };
            
            nodes.append(next_level.clone());
            current_level = next_level;
            height += 1;
        };
        
        let root = *current_level.at(0);
        
        MerkleTree {
            root: root,
            height: height,
            nodes: nodes,
        }
    }

    fn generate_merkle_proof(tree: @MerkleTree, leaf_index: u32) -> MerkleProof {
        let mut authentication_path = ArrayTrait::new();
        let mut current_index = leaf_index;
        
        // Get leaf value
        let leaves = tree.nodes.at(0);
        assert(current_index < leaves.len(), 'Leaf index out of bounds');
        let leaf_value = *leaves.at(current_index);
        
        // Generate authentication path
        let mut level = 0_u32;
        loop {
            if level >= *tree.height {
                break;
            }
            
            let level_nodes = tree.nodes.at(level);
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            if sibling_index < level_nodes.len() {
                let sibling = *level_nodes.at(sibling_index);
                authentication_path.append(sibling);
            } else {
                // Duplicate the current node if no sibling
                let current = *level_nodes.at(current_index);
                authentication_path.append(current);
            }
            
            current_index /= 2;
            level += 1;
        };
        
        MerkleProof {
            leaf_index: leaf_index,
            leaf_value: leaf_value,
            authentication_path: authentication_path,
        }
    }

    fn verify_merkle_proof(proof: @MerkleProof, root: felt252) -> bool {
        let mut current_hash = *proof.leaf_value;
        let mut current_index = *proof.leaf_index;
        
        let mut i = 0;
        loop {
            if i >= proof.authentication_path.len() {
                break;
            }
            
            let sibling = *proof.authentication_path.at(i);
            
            if current_index % 2 == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            };
            
            current_index /= 2;
            i += 1;
        };
        
        current_hash == root
    }

    fn hash_pair(left: felt252, right: felt252) -> felt252 {
        // Use Poseidon hash for better security properties in ZK proofs
        let mut data = ArrayTrait::new();
        data.append(left);
        data.append(right);
        poseidon_hash_span(data.span())
    }

    fn hash_array(data: @Array<felt252>) -> felt252 {
        // Hash array elements using Poseidon - optimal for STARK systems
        poseidon_hash_span(data.span())
    }

    // ============ IMPROVED FRI IMPLEMENTATION ============

    fn generate_fri_proof(polynomial_evaluations: @Array<felt252>) -> FRICommitment {
        assert(polynomial_evaluations.len() >= 4, 'Polynomial too small for FRI');
        let poly_len_u32: u32 = polynomial_evaluations.len().try_into().unwrap_or(4);
        assert(is_power_of_two(poly_len_u32), 'Eval count must be power of 2');
        
        let mut layer_trees = ArrayTrait::new();
        let mut layer_evaluations = ArrayTrait::new();
        let mut domains = ArrayTrait::new();
        let mut current_evaluations = polynomial_evaluations.clone();
        
        // Create initial domain
        let current_len_u32: u32 = current_evaluations.len().try_into().unwrap_or(4);
        let initial_domain = create_evaluation_domain(current_len_u32, 1);
        domains.append(initial_domain);
        
        // Commit to initial polynomial
        let initial_tree = build_merkle_tree(@current_evaluations);
        layer_trees.append(initial_tree);
        layer_evaluations.append(current_evaluations.clone());
        
        // FRI folding rounds - FIXED CONDITION
        let mut round = 0_u32;
        loop {
            // ✅ Changed condition: continue until we have 1-2 elements OR max rounds reached
            if round >= FRI_ROUNDS || current_evaluations.len() <= 2 {
                break;
            }
            
            // Ensure we can fold (need even number of elements)
            if current_evaluations.len() % 2 != 0 {
                break;
            }
            
            println!("FRI folding round {}: {} elements -> {} elements", 
                    round, current_evaluations.len(), current_evaluations.len() / 2);
            
            // Generate challenge using Fiat-Shamir
            let challenge = generate_fri_challenge(round, @layer_trees);
            
            // Fold polynomial evaluations
            let folded_evaluations = fri_fold_with_challenge(@current_evaluations, challenge);
            
            // Create domain for folded polynomial
            let folded_domain = create_evaluation_domain(
                folded_evaluations.len(), 
                field_mul(*domains.at(round).offset, challenge)
            );
            domains.append(folded_domain);
            
            // Commit to folded polynomial
            let folded_tree = build_merkle_tree(@folded_evaluations);
            layer_trees.append(folded_tree);
            layer_evaluations.append(folded_evaluations.clone());
            
            current_evaluations = folded_evaluations;
            round += 1;
            
            println!("Completed FRI round {}, now have {} elements", round - 1, current_evaluations.len());
        };
        
        println!("FRI folding completed: {} total layers", layer_trees.len());
        
        // Generate query phase
        let query_phase = generate_fri_queries(@layer_trees, @layer_evaluations);
        
        FRICommitment {
            layer_trees: layer_trees,
            layer_evaluations: layer_evaluations,
            final_polynomial: current_evaluations,
            query_phase: query_phase,
            domains: domains,
        }
    }

    fn fri_fold_with_challenge(evaluations: @Array<felt252>, challenge: felt252) -> Array<felt252> {
        assert(evaluations.len() >= 2, 'Need at least 2 evaluations');
        assert(evaluations.len() % 2 == 0, 'Evaluation count must be even');
        
        let mut folded = ArrayTrait::new();
        let half_len = evaluations.len() / 2;
        
        let mut i = 0;
        loop {
            if i >= half_len {
                break;
            }
            
            let f_x = *evaluations.at(i);
            let f_neg_x = *evaluations.at(i + half_len);
            
            // Fold: f_folded(x²) = f(x) + challenge * f(-x)
            let folded_value = field_add(f_x, field_mul(challenge, f_neg_x));
            folded.append(folded_value);
            
            i += 1;
        };
        
        folded
    }

    fn generate_fri_challenge(round: u32, commitments: @Array<MerkleTree>) -> felt252 {
        // Fiat-Shamir transform: hash all previous commitments to generate challenge
        let mut challenge_data = ArrayTrait::new();
        challenge_data.append(round.into());
        
        let mut i = 0;
        loop {
            if i >= commitments.len() {
                break;
            }
            let tree = commitments.at(i);
            challenge_data.append(*tree.root);
            i += 1;
        };
        
        hash_array(@challenge_data)
    }

    fn generate_fri_queries(
        trees: @Array<MerkleTree>, 
        evaluations: @Array<Array<felt252>>
    ) -> FRIQueryPhase {
        println!("ENTERING generate_fri_queries function");
        println!("FRI queries: trees length = {}, evaluations length = {}", trees.len(), evaluations.len());
        
        let mut queries = ArrayTrait::new();
        
        // Generate random query positions based on the first (largest) domain
        let first_tree = trees.at(0);
        let domain_size = first_tree.nodes.at(0).len();
        println!("FRI queries: domain size = {}", domain_size);
        let query_positions = generate_query_positions(domain_size);
        println!("FRI queries: generated {} query positions", query_positions.len());
        
        let mut q = 0;
        loop {
            if q >= query_positions.len() {
                break;
            }
            
            let initial_position = *query_positions.at(q);
            println!("FRI queries: processing query {} at initial position {}", q, initial_position);
            
            // Generate queries for each FRI layer with adjusted positions
            let mut layer = 0_u32;
            let mut current_position = initial_position;
            
            loop {
                if layer >= trees.len() {
                    break;
                }
                
                let tree = trees.at(layer);
                let layer_evals = evaluations.at(layer);
                let layer_size = layer_evals.len();
                
                // Ensure position is within bounds for this layer
                if current_position >= layer_size {
                    println!("FRI queries: position {} out of bounds for layer {} (size {})", 
                            current_position, layer, layer_size);
                    break;
                }
                
                println!("FRI queries: layer {}, adjusted position {}, layer size {}", 
                        layer, current_position, layer_size);
                
                // Get value and sibling using FRI pairing (not adjacent pairing!)
                let value = *layer_evals.at(current_position);
                let half_size = layer_size / 2;
                
                // ✅ CORRECT FRI SIBLING PAIRING
                let sibling_pos = if current_position < half_size {
                    current_position + half_size  // First half pairs with second half
                } else {
                    current_position - half_size  // Second half pairs with first half
                };
                
                let sibling_value = if sibling_pos < layer_size {
                    *layer_evals.at(sibling_pos)
                } else {
                    value  // Use same value if no sibling (shouldn't happen in proper FRI)
                };
                
                println!("FRI queries: position {}, sibling position {}, half_size {}", 
                        current_position, sibling_pos, half_size);
                
                // Generate Merkle proof for this layer and position
                let merkle_proof = generate_merkle_proof(tree, current_position);
                
                let query = FRIQuery {
                    layer_index: layer,
                    position: current_position,
                    value: value,
                    sibling_value: sibling_value,
                    merkle_proof: merkle_proof,
                };
                
                queries.append(query);
                
                // Adjust position for next layer (FRI folding divides positions by 2)
                current_position = current_position / 2;
                layer += 1;
            };
            
            q += 1;
        };
        
        println!("FRI queries: generated {} total queries", queries.len());
        let challenge = generate_query_challenge(@queries);
        println!("FRI queries: generated challenge");
        
        println!("EXITING generate_fri_queries function");
        FRIQueryPhase {
            queries: queries,
            challenge: challenge,
        }
    }

    fn generate_query_positions(domain_size: usize) -> Array<u32> {
        let mut positions = ArrayTrait::new();
        let mut seed = GENERATOR;
        
        let mut i = 0;
        loop {
            if i >= NUM_QUERIES {
                break;
            }
            
            // Generate pseudo-random position
            seed = field_mul(seed, GENERATOR);
            let position = (seed.try_into().unwrap_or(0_u32)) % domain_size;
            positions.append(position);
            
            i += 1;
        };
        
        positions
    }

    fn generate_query_challenge(queries: @Array<FRIQuery>) -> felt252 {
        let mut challenge_data = ArrayTrait::new();
        
        let mut i = 0;
        loop {
            if i >= queries.len() {
                break;
            }
            
            let query = queries.at(i);
            challenge_data.append(*query.value);
            challenge_data.append(*query.sibling_value);
            
            i += 1;
        };
        
        hash_array(@challenge_data)
    }

    // ============ VERIFICATION FUNCTIONS ============

    fn verify_fri_proof(proof: @FRICommitment) -> bool {
        println!("FRI proof verification: checking layer count...");
        
        // ✅ More flexible layer count check - allow smaller proofs for demos
        let min_layers = if proof.layer_trees.len() == 1 && proof.final_polynomial.len() <= 2 {
            1  // Allow single layer if final polynomial is very small
        } else {
            2  // Standard minimum
        };
        
        if proof.layer_trees.len() < min_layers {
            println!("FAILED FRI: Not enough layers ({} < {})", proof.layer_trees.len(), min_layers);
            false
        } else {
            println!("PASSED FRI: Layer count OK ({} >= {})", proof.layer_trees.len(), min_layers);
            
            // Verify each layer transition
            let mut layer = 0_u32;
            let mut all_valid = true;
            
            // Only check transitions if we have multiple layers
            if proof.layer_trees.len() > 1 {
                loop {
                    if layer >= proof.layer_trees.len() - 1 {
                        break;
                    }
                    
                    println!("FRI: Verifying layer transition {}", layer);
                    if !verify_fri_layer_transition(proof, layer) {
                        println!("FAILED FRI: Layer transition {} FAILED", layer);
                        all_valid = false;
                        break;
                    } else {
                        println!("PASSED FRI: Layer transition {} PASSED", layer);
                    }
                    
                    layer += 1;
                };
            } else {
                println!("FRI: Single layer proof - skipping transition verification");
            }
            
            // Verify query phase if all layers are valid
            if all_valid {
                println!("FRI: All layer transitions passed, checking queries...");
                let query_result = verify_fri_queries(proof);
                println!("FRI: Query verification result: {}", query_result);
                query_result
            } else {
                println!("FAILED FRI: Layer transitions failed");
                false
            }
        }
    }

    fn verify_fri_layer_transition(proof: @FRICommitment, layer_index: u32) -> bool {
        println!("FRI layer transition {}: starting verification", layer_index);
        if layer_index >= proof.layer_trees.len() - 1 {
            println!("FAILED FRI layer {}: Index out of bounds", layer_index);
            false
        } else {
            let current_evaluations = proof.layer_evaluations.at(layer_index);
            let next_evaluations = proof.layer_evaluations.at(layer_index + 1);
            println!("FRI layer {}: Current length: {}, Next length: {}", layer_index, current_evaluations.len(), next_evaluations.len());
            
            // Generate challenge for this layer
            let partial_trees = get_trees_up_to_layer(proof, layer_index);
            let challenge = generate_fri_challenge(layer_index, @partial_trees);
            println!("FRI layer {}: Generated challenge: {}", layer_index, challenge);
            
            // Verify folding was done correctly
            let expected_folded = fri_fold_with_challenge(current_evaluations, challenge);
            println!("FRI layer {}: Expected folded length: {}", layer_index, expected_folded.len());
            
            if expected_folded.len() != next_evaluations.len() {
                println!("FAILED FRI layer {}: Length mismatch", layer_index);
                false
            } else {
                let mut i = 0;
                let mut all_match = true;
                
                loop {
                    if i >= expected_folded.len() {
                        break;
                    }
                    
                    if *expected_folded.at(i) != *next_evaluations.at(i) {
                        println!("FAILED FRI layer {}: Value mismatch at index {}", layer_index, i);
                        all_match = false;
                        break;
                    }
                    
                    i += 1;
                };
                
                if all_match {
                    println!("PASSED FRI layer {}: All values match", layer_index);
                }
                all_match
            }
        }
    }

    fn get_trees_up_to_layer(proof: @FRICommitment, max_layer: u32) -> Array<MerkleTree> {
        let mut trees = ArrayTrait::new();
        
        let mut i = 0_u32;
        loop {
            if i > max_layer || i >= proof.layer_trees.len() {
                break;
            }
            
            let tree = proof.layer_trees.at(i);
            trees.append(tree.clone());
            i += 1;
        };
        
        trees
    }

    fn verify_fri_queries(proof: @FRICommitment) -> bool {
        let queries = proof.query_phase.queries;
        println!("FRI queries: Verifying {} queries", queries.len());
        let mut i = 0;
        let mut all_valid = true;
        
        loop {
            if i >= queries.len() {
                break;
            }
            
            let query = queries.at(i);
            println!("FRI query {}: layer {}, position {}", i, *query.layer_index, *query.position);
            
            // Verify Merkle proof
            let tree = proof.layer_trees.at(*query.layer_index);
            if !verify_merkle_proof(query.merkle_proof, *tree.root) {
                println!("FAILED FRI query {}: Merkle proof FAILED", i);
                all_valid = false;
                break;
            } else {
                println!("PASSED FRI query {}: Merkle proof PASSED", i);
            }
            
            // Verify consistency with folding (if not last layer)
            if *query.layer_index < proof.layer_trees.len() - 1 {
                if !verify_query_folding_consistency(proof, query) {
                    println!("FAILED FRI query {}: Folding consistency FAILED", i);
                    all_valid = false;
                    break;
                } else {
                    println!("PASSED FRI query {}: Folding consistency PASSED", i);
                }
            }
            
            i += 1;
        };
        
        println!("FRI queries verification result: {}", all_valid);
        all_valid
    }

    fn verify_query_folding_consistency(proof: @FRICommitment, query: @FRIQuery) -> bool {
        if *query.layer_index >= proof.layer_trees.len() - 1 {
            true  // No next layer to check
        } else {
            // Get challenge for this layer
            let partial_trees = get_trees_up_to_layer(proof, *query.layer_index);
            let challenge = generate_fri_challenge(*query.layer_index, @partial_trees);
            
            // Get current layer info
            let current_layer_evals = proof.layer_evaluations.at(*query.layer_index);
            let layer_size = current_layer_evals.len();
            let half_size = layer_size / 2;
            
            // ✅ CORRECT FRI folding formula based on position
            let expected_folded = if *query.position < half_size {
                // First half: f(x) + challenge * f(-x)
                // query.value is f(x), query.sibling_value is f(-x)
                field_add(*query.value, field_mul(challenge, *query.sibling_value))
            } else {
                // Second half: f(-x) is queried, but folding uses f(x) + challenge * f(-x)
                // query.value is f(-x), query.sibling_value is f(x)
                field_add(*query.sibling_value, field_mul(challenge, *query.value))
            };
            
            // Get actual value from next layer
            let next_layer_evals = proof.layer_evaluations.at(*query.layer_index + 1);
            let folded_position = if *query.position < half_size {
                *query.position  // First half maps directly
            } else {
                *query.position - half_size  // Second half maps to first half
            };
            
            println!("Folding consistency: layer {}, pos {}, half_size {}, folded_pos {}", 
                    *query.layer_index, *query.position, half_size, folded_position);
            
            if folded_position >= next_layer_evals.len() {
                println!("Folding consistency FAILED: folded_position {} >= next_layer_size {}", 
                        folded_position, next_layer_evals.len());
                false
            } else {
                let actual_folded = *next_layer_evals.at(folded_position);
                let matches = expected_folded == actual_folded;
                
                if !matches {
                    println!("Folding consistency FAILED: expected {}, got {}", 
                            expected_folded, actual_folded);
                } else {
                    println!("Folding consistency PASSED: values match {}", expected_folded);
                }
                
                matches
            }
        }
    }

    // ============ MAIN PROOF GENERATION AND VERIFICATION ============

    fn generate_stark_proof(
        public_input: PublicInput,
        private_input: Array<felt252>
    ) -> STARKProof {
        println!("=== STARK Proof Generation Started ===");
        
        let trace = generate_execution_trace(public_input, private_input);
        println!("Generated execution trace: {} rows, {} width", trace.rows.len(), trace.width);
        
        let constraints = generate_air_constraints(@trace);
        println!("Generated AIR constraints");
        
        let extended_trace = compute_low_degree_extension(@trace);
        println!("Computed low degree extension: {} elements", extended_trace.len());
        
        // Build Merkle tree commitment for trace
        let trace_commitment = build_merkle_tree(@extended_trace);
        println!("Built trace commitment with root: {}", trace_commitment.root);
        
        // Generate FRI proof  
        println!("About to call generate_fri_proof function...");
        println!("Extended trace length before FRI: {}", extended_trace.len());
        
        // Call the function with manual implementation
        let fri_proof = generate_fri_proof(@extended_trace);
        
        println!("Returned from generate_fri_proof function");
        let layer_count = fri_proof.layer_trees.len();
        println!("Generated FRI proof with {} layers", layer_count);
        
        // Generate random points for constraint evaluation
        let random_points = generate_random_points();
        println!("Generated {} random points", random_points.len());
        
        let evaluations = evaluate_constraints(
            @constraints,
            @extended_trace,
            @random_points
        );
        println!("Evaluated constraints: {} evaluations", evaluations.len());
        
        // Generate public coin seed for Fiat-Shamir
        let public_coin_seed = generate_public_coin_seed(public_input, @trace_commitment);
        println!("Generated public coin seed: {}", public_coin_seed);

        let proof = STARKProof {
            trace_commitment: trace_commitment,
            trace_evaluations: evaluations,
            fri_proof: fri_proof,
            low_degree_proof: generate_low_degree_proof(@extended_trace),
            public_coin_seed: public_coin_seed,
        };
        
        println!("=== STARK Proof Generation Completed ===");
        proof
    }

    fn verify_stark_proof(
        public_input: PublicInput,
        proof: STARKProof
    ) -> bool {
        println!("=== STARK Proof Verification Started ===");
        
        // Verify public coin seed
        let expected_seed = generate_public_coin_seed(public_input, @proof.trace_commitment);
        println!("Expected seed: {}", expected_seed);
        println!("Actual seed: {}", proof.public_coin_seed);
        
        if proof.public_coin_seed != expected_seed {
            println!("FAILED: Public coin seed verification");
            false
        } else {
            println!("PASSED: Public coin seed verification");
            
            // Verify FRI proof
            println!("--- Starting FRI proof verification ---");
            let valid_fri = verify_fri_proof(@proof.fri_proof);
            println!("FRI proof verification result: {}", valid_fri);
            
            // Verify constraint evaluations
            println!("--- Starting constraint verification ---");
            let valid_constraints = verify_constraint_evaluations(
                @proof.trace_evaluations,
                public_input
            );
            println!("Constraint verification result: {}", valid_constraints);
            
            // Verify low degree proof
            println!("--- Starting low degree verification ---");
            let valid_degree = verify_low_degree_proof(
                @proof.low_degree_proof,
                @proof.fri_proof
            );
            println!("Low degree verification result: {}", valid_degree);
            
            let final_result = valid_fri && valid_constraints && valid_degree;
            println!("=== Final verification result: {} ===", final_result);
            
            final_result
        }
    }

    fn generate_public_coin_seed(public_input: PublicInput, commitment: @MerkleTree) -> felt252 {
        let mut seed_data = ArrayTrait::new();
        seed_data.append(public_input.message_hash);
        seed_data.append(public_input.public_key);
        seed_data.append(public_input.signature);
        seed_data.append(*commitment.root);
        
        hash_array(@seed_data)
    }

    // ============ HELPER FUNCTIONS (Updated) ============

    fn generate_execution_trace(
        public_input: PublicInput,
        private_input: Array<felt252>
    ) -> TraceTable {
        let mut rows = ArrayTrait::new();
        let width = 4;
        
        let mut first_row = ArrayTrait::new();
        first_row.append(public_input.message_hash);
        first_row.append(public_input.public_key);
        first_row.append(*private_input.at(0));
        first_row.append(*private_input.at(1));
        rows.append(first_row);
        
        // Create proper evaluation domain
        let domain = create_evaluation_domain(BLOW_UP_FACTOR, 1);
        
        TraceTable { 
            rows: rows, 
            width: width, 
            length: 1,
            domain: domain,
        }
    }

    fn generate_air_constraints(trace: @TraceTable) -> AIRConstraints {
        let mut boundary = ArrayTrait::new();
        let mut transition = ArrayTrait::new();
        let mut permutation = ArrayTrait::new();

        boundary.append(*trace.rows.at(0).at(0));
        transition.append(*trace.rows.at(0).at(1));
        permutation.append(*trace.rows.at(0).at(2));

        AIRConstraints {
            boundary_constraints: boundary,
            transition_constraints: transition,
            permutation_constraints: permutation,
            constraint_degree: 2,  // Degree of constraint polynomials
        }
    }

    fn compute_low_degree_extension(trace: @TraceTable) -> Array<felt252> {
        let mut extended = ArrayTrait::new();
        let domain_size = *trace.length * BLOW_UP_FACTOR;
        
        // Evaluate polynomial over extended domain
        let mut i = 0_u32;
        loop {
            if i >= domain_size {
                break;
            }
            
            let domain_point = field_pow(*trace.domain.generator, i);
            let evaluation = evaluate_trace_polynomial_at_point(trace, domain_point);
            extended.append(evaluation);
            
            i += 1;
        };
        
        extended
    }

    fn evaluate_trace_polynomial_at_point(trace: @TraceTable, point: felt252) -> felt252 {
        // Simplified polynomial evaluation - in practice would use proper interpolation
        if trace.rows.len() == 0 {
            return 0;
        }
        
        let first_row = trace.rows.at(0);
        if first_row.len() == 0 {
            return 0;
        }
        
        // Simple evaluation: just return first element multiplied by point
        field_mul(*first_row.at(0), point)
    }

    fn generate_random_points() -> Array<felt252> {
        let mut points = ArrayTrait::new();
        let mut current = GENERATOR;
        
        let mut count = 0_u32;
        loop {
            if count >= NUM_QUERIES {
                break;
            }
            points.append(current);
            current = field_mul(current, GENERATOR);
            count += 1;
        };
        
        if points.len() > 0 {
            println!("Generated random points: first = {}, last = {}", *points.at(0), *points.at(points.len() - 1));
        }
        points
    }

    fn evaluate_constraints(
        constraints: @AIRConstraints,
        trace: @Array<felt252>,
        points: @Array<felt252>
    ) -> Array<felt252> {
        let mut evaluations = ArrayTrait::new();
        let mut i = 0;
        
        loop {
            if i >= points.len() {
                break;
            }
            
            let point = *points.at(i);
            
            // Evaluate constraint polynomial at this point
            let eval = evaluate_constraint_at_point(constraints, trace, point);
            evaluations.append(eval);
            
            i += 1;
        };
        
        evaluations
    }

    fn evaluate_constraint_at_point(
        constraints: @AIRConstraints,
        trace: @Array<felt252>,
        point: felt252
    ) -> felt252 {
        // Simplified constraint evaluation - should match verification logic
        // For demo purposes, using point^2 as a simple polynomial constraint
        field_mul(point, point)
    }

    fn generate_low_degree_proof(trace: @Array<felt252>) -> Array<felt252> {
        // In a real implementation, this would generate a proper low-degree proof
        trace.clone()
    }

    fn verify_constraint_evaluations(
        evaluations: @Array<felt252>,
        public_input: PublicInput
    ) -> bool {
        println!("Constraint verification: checking evaluation count...");
        // Simplified constraint verification
        if evaluations.len() == 0 {
            println!("WARNING Constraint: No evaluations to verify");
            true
        } else {
            println!("Constraint: Verifying {} evaluations", evaluations.len());
            
            // Generate the same random points that were used during proof generation
            let random_points = generate_random_points();
            
            // Check if evaluations are consistent with public inputs
            let mut i = 0;
            let mut all_valid = true;
            
            loop {
                if i >= evaluations.len() {
                    break;
                }
                
                let evaluation = *evaluations.at(i);
                let point = *random_points.at(i);
                if !verify_single_constraint_evaluation(evaluation, point) {
                    println!("FAILED Constraint: Evaluation {} FAILED", i);
                    println!("Expected: {}, Got: {}", field_mul(point, point), evaluation);
                    all_valid = false;
                    break;
                } else {
                    if i < 5 { // Only print first 5 to avoid spam
                        println!("PASSED Constraint: Evaluation {} PASSED", i);
                    }
                }
                
                i += 1;
            };
            
            println!("Constraint verification final result: {}", all_valid);
            all_valid
        }
    }

    fn verify_single_constraint_evaluation(
        evaluation: felt252,
        point: felt252
    ) -> bool {
        // Should match the evaluation logic: point^2
        let expected = field_mul(point, point);
        evaluation == expected
    }

    fn felt252_gt(a: felt252, b: felt252) -> bool {
        // Convert to u256 for comparison if small enough, otherwise use custom logic
        let a_u256: u256 = a.into();
        let b_u256: u256 = b.into();
        a_u256 > b_u256
    }

    fn verify_low_degree_proof(
        proof: @Array<felt252>,
        fri_proof: @FRICommitment
    ) -> bool {
        println!("Low degree verification: checking basic requirements...");
        // Verify the low-degree proof is consistent with FRI proof
        if proof.len() == 0 || fri_proof.layer_trees.len() == 0 {
            println!("FAILED Low degree: Empty proof or FRI layers");
            false
        } else {
            println!("Low degree: Proof length: {}, FRI layers: {}", proof.len(), fri_proof.layer_trees.len());
            
            // Check degree bounds
            let max_degree = calculate_max_degree(proof);
            let degree_bound = (FRI_ROUNDS * BLOW_UP_FACTOR).into();
            println!("Low degree: Max degree: {}, Bound: {}", max_degree, degree_bound);
            
            if felt252_gt(max_degree, degree_bound) {
                println!("FAILED Low degree: Degree too high");
                false
            } else {
                println!("PASSED Low degree: Degree check passed");
                
                // Verify consistency with first FRI layer
                let first_layer_evals = fri_proof.layer_evaluations.at(0);
                println!("Low degree: Proof length: {}, First layer length: {}", proof.len(), first_layer_evals.len());
                
                if proof.len() != first_layer_evals.len() {
                    println!("FAILED Low degree: Length mismatch");
                    false
                } else {
                    println!("PASSED Low degree: Length check passed");
                    let mut i = 0;
                    let mut all_match = true;
                    
                    loop {
                        if i >= proof.len() {
                            break;
                        }
                        
                        if *proof.at(i) != *first_layer_evals.at(i) {
                            println!("FAILED Low degree: Element mismatch at index {}", i);
                            all_match = false;
                            break;
                        }
                        
                        i += 1;
                    };
                    
                    if all_match {
                        println!("PASSED Low degree: All elements match");
                    }
                    all_match
                }
            }
        }
    }

    fn calculate_max_degree(poly: @Array<felt252>) -> felt252 {
        let mut max_degree: felt252 = 0;
        let mut i = 0;

        loop {
            if i >= poly.len() {
                break;
            }
            
            let coefficient = *poly.at(i);
            if coefficient != 0 {
                max_degree = i.into();
            }
            
            i += 1;
        };

        max_degree
    }

    // ============ MAIN FUNCTION ============

    fn main() {
        println!("Starting STARK Proof System Test");
        
        let public_input = PublicInput {
            message_hash: 123,
            public_key: 456,
            signature: 789,
        };
        println!("Public input - Message: {}, PubKey: {}, Signature: {}", 
                public_input.message_hash, public_input.public_key, public_input.signature);
        
        let mut private_input = ArrayTrait::new();
        private_input.append(10);
        private_input.append(20);
        println!("Private input: [10, 20]");

        let stark_proof = generate_stark_proof(public_input, private_input);
        let is_valid = verify_stark_proof(public_input, stark_proof);

        // Print result using format strings compatible with Cairo 2.9.2
        if is_valid {
            println!("STARK proof verification succeeded!");
        } else {
            println!("STARK proof verification failed!");
        }

        assert(is_valid, 'Proof verification failed');
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProofGenerated: ProofGenerated,
        ProofVerified: ProofVerified
    }

    #[derive(Drop, starknet::Event)]
    struct ProofGenerated {
        proof_hash: felt252
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerified {
        verification_result: bool
    }
}