use core::array::ArrayTrait;
use core::option::OptionTrait;
use core::traits::TryInto;
use core::hash::{HashStateTrait, Hash};
use core::pedersen::pedersen;
use core::traits::Into;

#[starknet::contract]
mod SignatureVerificationSTARK {
    use super::{ArrayTrait, Hash, pedersen, OptionTrait, TryInto, Into};
    use core::hash::HashStateTrait;

    const FIELD_PRIME: felt252 = 0x400000000000008100000000000000000000000000000000000000000000001;
    const HALF_PRIME: felt252 = 0x200000000000004080000000000000000000000000000000000000000000000;
    const GENERATOR: felt252 = 3;
    const FRI_ROUNDS: u32 = 8;
    const BLOW_UP_FACTOR: felt252 = 4;
    const BLOW_UP_FACTOR_U32: u32 = 4;

    #[storage]
    struct Storage {
        proofs: LegacyMap::<felt252, bool>,
    }

    #[derive(Drop, Serde)]
    struct AIRConstraints {
        boundary_constraints: Array<felt252>,
        transition_constraints: Array<felt252>,
        permutation_constraints: Array<felt252>
    }

    #[derive(Drop, Serde)]
    struct FRICommitment {
        layers: Array<Array<felt252>>,
        final_polynomial: Array<felt252>
    }

    #[derive(Drop, Serde)]
    struct STARKProof {
        trace_commitment: Array<felt252>,
        trace_evaluation: Array<felt252>,
        fri_commitments: FRICommitment,
        low_degree_proof: Array<felt252>
    }

    #[derive(Drop, Serde)]
    struct TraceTable {
        rows: Array<Array<felt252>>,
        width: usize,
        length: usize
    }

    #[derive(Drop, Copy, Serde)]
    struct PublicInput {
        message_hash: felt252,
        public_key: felt252,
        signature: felt252,
    }

    // Helper functions for felt252 arithmetic
    fn felt252_mul(a: felt252, b: felt252) -> felt252 {
        if a == 0 || b == 0 {
            return 0;
        }
        let result = a * b;
        if result == 0 {
            panic!("Multiplication overflow");
        }
        result
    }

    fn felt252_add(a: felt252, b: felt252) -> felt252 {
        let result = a + b;
        // For felt252, simple addition is safe as it's performed modulo the field prime
        result
    }

    #[external(v0)]
    fn generate_stark_proof(
        self: @ContractState, 
        public_input: PublicInput,
        private_input: Array<felt252>
    ) -> STARKProof {
        let trace = generate_execution_trace(public_input, private_input);
        let constraints = generate_air_constraints(@trace);
        let extended_trace = compute_low_degree_extension(@trace);
        let trace_commitment = commit_to_polynomial(@extended_trace);
        let fri_proof = generate_fri_proof(@extended_trace);
        let random_points = generate_random_points();
        
        let evaluations = evaluate_constraints(
            @constraints,
            @extended_trace,
            @random_points
        );

        STARKProof {
            trace_commitment: trace_commitment,
            trace_evaluation: evaluations,
            fri_commitments: fri_proof,
            low_degree_proof: generate_low_degree_proof(@extended_trace)
        }
    }

    #[external(v0)]
    fn verify_stark_proof(
        self: @ContractState,
        public_input: PublicInput,
        proof: STARKProof
    ) -> bool {
        let valid_fri = verify_fri_proof(@proof.fri_commitments);
        let valid_constraints = verify_constraint_evaluations(
            @proof.trace_evaluation,
            public_input
        );
        let valid_degree = verify_low_degree_proof(
            @proof.low_degree_proof,
            @proof.fri_commitments
        );

        valid_fri && valid_constraints && valid_degree
    }

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
        
        TraceTable { rows: rows, width: width, length: 1 }
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
            permutation_constraints: permutation
        }
    }

    fn compute_low_degree_extension(trace: @TraceTable) -> Array<felt252> {
        let mut extended = ArrayTrait::new();
        let length_felt = felt252_from_u32(*trace.length);
        let domain_size = felt252_mul(length_felt, BLOW_UP_FACTOR);
        
        let mut current: felt252 = 1;
        let mut count = 0_u32;
        let domain_size_u32 = *trace.length * BLOW_UP_FACTOR_U32;
        
        loop {
            if count >= domain_size_u32 {
                break;
            }
            extended.append(current);
            current = felt252_mul(current, GENERATOR);
            count += 1;
        };
        
        extended
    }

    fn felt252_from_u32(value: u32) -> felt252 {
        value.into()
    }

    fn commit_to_polynomial(poly: @Array<felt252>) -> Array<felt252> {
        let mut commitments = ArrayTrait::new();
        let mut current_hash: felt252 = 0;
        
        let mut i = 0;
        loop {
            if i >= poly.len() {
                break;
            }
            current_hash = pedersen(current_hash, *poly.at(i));
            commitments.append(current_hash);
            i += 1;
        };
        
        commitments
    }

    fn generate_fri_proof(polynomial: @Array<felt252>) -> FRICommitment {
        let mut layers = ArrayTrait::new();
        let mut current_layer = polynomial.clone();

        let mut i: u32 = 0;
        loop {
            if i >= FRI_ROUNDS {
                break;
            }
            let folded = fri_fold_polynomial(@current_layer);
            let mut layer = ArrayTrait::new();
            layer.append(pedersen(0, *folded.at(0)));
            layers.append(layer);
            current_layer = folded;
            i += 1;
        };

        FRICommitment {
            layers: layers,
            final_polynomial: current_layer
        }
    }

    fn fri_fold_polynomial(poly: @Array<felt252>) -> Array<felt252> {
        let mut folded = ArrayTrait::new();
        let half_len = poly.len() / 2;
        
        let mut i = 0;
        loop {
            if i >= half_len {
                break;
            }
            let left = *poly.at(i);
            let right = *poly.at(i + half_len);
            let gen_right = felt252_mul(GENERATOR, right);
            let combined = felt252_add(left, gen_right);
            folded.append(combined);
            i += 1;
        };
        
        folded
    }

    fn generate_random_points() -> Array<felt252> {
        let mut points = ArrayTrait::new();
        let mut current = GENERATOR;
        let target_u32 = 32_u32;
        
        let mut count = 0_u32;
        loop {
            if count >= target_u32 {
                break;
            }
            points.append(current);
            current = felt252_mul(current, GENERATOR);
            count += 1;
        };
        
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
            let eval = felt252_mul(point, point);
            evaluations.append(eval);
            i += 1;
        };
        
        evaluations
    }

    fn generate_low_degree_proof(trace: @Array<felt252>) -> Array<felt252> {
        let mut proof = ArrayTrait::new();
        let mut i = 0;
        
        loop {
            if i >= trace.len() {
                break;
            }
            proof.append(*trace.at(i));
            i += 1;
        };
        
        proof
    }

    fn verify_fri_proof(proof: @FRICommitment) -> bool {
        let mut valid = true;
        let mut i = 0;
        
        loop {
            if i >= proof.layers.len() - 1 {
                break;
            }
            let current_layer = proof.layers.at(i);
            let next_layer = proof.layers.at(i + 1);
            valid = verify_fri_fold(current_layer, next_layer);
            if !valid {
                break;
            }
            i += 1;
        };
        
        valid
    }

    fn verify_fri_fold(current: @Array<felt252>, next: @Array<felt252>) -> bool {
        *current.at(0) == *next.at(0)
    }

    fn verify_constraint_evaluations(
        evaluations: @Array<felt252>,
        public_input: PublicInput
    ) -> bool {
        let mut valid = true;
        let mut i = 0;
        
        loop {
            if i >= evaluations.len() {
                break;
            }
            let evaluation = *evaluations.at(i);
            // Public input is now Copy so it can be used multiple times
            if !verify_single_constraint(evaluation, public_input, i.into()) {
                valid = false;
                break;
            }
            i += 1;
        };
        
        valid
    }

    fn verify_single_constraint(
        evaluation: felt252,
        public_input: PublicInput,
        index: felt252
    ) -> bool {
        evaluation == felt252_mul(index, index)
    }

    fn verify_low_degree_proof(
        proof: @Array<felt252>,
        fri_proof: @FRICommitment
    ) -> bool {
        // Check if proof or fri_proof layers are empty
        if proof.len() == 0 || fri_proof.layers.len() == 0 {
            false
        } else {
            // Verify the degree of the polynomial is within bounds
            let max_degree = calculate_max_degree(proof);
            let degree_bound = felt252_from_u32(FRI_ROUNDS * BLOW_UP_FACTOR_U32);
            
            // Use felt252_gt instead of >
            if felt252_gt(max_degree, degree_bound) {
                false
            } else {
                // Verify consistency between proof and FRI layers
                let is_consistent = verify_proof_consistency(proof, fri_proof);
                if !is_consistent {
                    false
                } else {
                    // Verify FRI layer transitions
                    let mut current_layer = proof.clone();
                    let mut i: u32 = 0;
                    let mut valid = true;

                    loop {
                        if i >= fri_proof.layers.len() {
                            break;
                        }
                        // Get the next FRI layer commitment
                        let next_layer_commitment = fri_proof.layers.at(i);
                        // Compute the folded polynomial
                        let folded = fri_fold_polynomial(@current_layer);
                        // Verify the commitment matches
                        let computed_commitment = commit_to_polynomial(@folded);
                        if computed_commitment.len() == 0 || 
                        *computed_commitment.at(0) != *next_layer_commitment.at(0) {
                            valid = false;
                            break;
                        }
                        current_layer = folded;
                        i += 1;
                    };

                    if !valid {
                        false
                    } else {
                        // Verify final polynomial matches
                        let final_layer_commitment = commit_to_polynomial(@current_layer);
                        
                        // Create a fresh reference to final_polynomial to avoid double referencing
                        let final_polynomial = fri_proof.final_polynomial.clone();
                        let final_fri_commitment = commit_to_polynomial(@final_polynomial);

                        if final_layer_commitment.len() == 0 || 
                        final_fri_commitment.len() == 0 || 
                        *final_layer_commitment.at(0) != *final_fri_commitment.at(0) {
                            false
                        } else {
                            // Verify degree of final polynomial
                            let final_degree = calculate_max_degree(@final_polynomial);
                            let bound = felt252_from_u32(BLOW_UP_FACTOR_U32);

                            if felt252_gt(final_degree, bound) {
                                false
                            } else {
                                true
                            }   
                        }
                    }
                }
            }
        }
    }


    // Helper function to calculate maximum degree of polynomial
    fn calculate_max_degree(poly: @Array<felt252>) -> felt252 {
        let mut max_degree: felt252 = 0;
        let mut i = 0;

        loop {
            if i >= poly.len() {
                break;
            }
            
            let coefficient = *poly.at(i);
            if coefficient != 0 {
                max_degree = felt252_from_u32(i.try_into().unwrap());
            }
            
            i += 1;
        };

        max_degree
    }

    // helper function for felt252 comparison
    fn felt252_gt(a: felt252, b: felt252) -> bool {
        let difference = a - b;

        if difference == 0 {
            return false;
        }

        !is_upper_half(difference)  
    }

    fn is_upper_half(value: felt252) -> bool {
        // Check if value - HALF_PRIME has non-zero value in upper bits
        let shifted = value - HALF_PRIME;
        shifted != 0 && (value - shifted != HALF_PRIME)
    }

    // Helper function to verify consistency between proof and FRI layers
    fn verify_proof_consistency(
        proof: @Array<felt252>,
        fri_proof: @FRICommitment
    ) -> bool {
        // Verify initial commitment matches first FRI layer
        let initial_commitment = commit_to_polynomial(proof);
        if initial_commitment.len() == 0 || fri_proof.layers.len() == 0 {
            false
        } else {
            let first_fri_layer = fri_proof.layers.at(0);
            if first_fri_layer.len() == 0 {
                false
            } else {
                let commitment_value = initial_commitment.at(0);
                let fri_layer_value = first_fri_layer.at(0);
                *commitment_value == *fri_layer_value
            }
        }
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


