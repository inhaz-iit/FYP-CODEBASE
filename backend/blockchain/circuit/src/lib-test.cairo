#[cfg(test)]
mod tests {
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use core::array::ArrayTrait;
    use super::{SignatureVerificationSTARK};
    use starknet::ContractAddress;
    use core::pedersen::pedersen;

    // Helper function to create test public inputs
    fn create_test_public_input() -> PublicInput {
        PublicInput {
            // Sample test values - in real usage these would be actual signature components
            message_hash: 0x123456789abcdef,
            public_key: 0x987654321fedcba,
            signature: 0xabcdef123456789
        }
    }

    // Helper function to create test private inputs
    fn create_test_private_input() -> Array<felt252> {
        let mut private_input = ArrayTrait::new();
        // r value from ECDSA signature
        private_input.append(0x111111111111111);
        // s value from ECDSA signature
        private_input.append(0x222222222222222);
        private_input
    }

    #[test]
    fn test_proof_generation() {
        // Create test inputs
        let public_input = create_test_public_input();
        let private_input = create_test_private_input();

        // Generate proof
        let proof = SignatureVerificationSTARK::generate_stark_proof(
            @public_input,
            private_input
        );

        // Verify proof is not empty
        assert(!proof.trace_commitment.is_empty(), 'Trace commitment empty');
        assert(!proof.trace_evaluation.is_empty(), 'Trace evaluation empty');
        assert(!proof.fri_commitments.layers.is_empty(), 'FRI commitments empty');
        assert(!proof.low_degree_proof.is_empty(), 'Low degree proof empty');
    }

    #[test]
    fn test_proof_verification() {
        // Create test inputs
        let public_input = create_test_public_input();
        let private_input = create_test_private_input();

        // Generate proof
        let proof = SignatureVerificationSTARK::generate_stark_proof(
            @public_input,
            private_input
        );

        // Verify proof
        let verification_result = SignatureVerificationSTARK::verify_stark_proof(
            @public_input,
            proof
        );

        assert(verification_result, 'Proof verification failed');
    }

    #[test]
    fn test_invalid_proof_rejection() {
        // Create test inputs
        let public_input = create_test_public_input();
        let private_input = create_test_private_input();

        // Generate proof
        let mut proof = SignatureVerificationSTARK::generate_stark_proof(
            @public_input,
            private_input
        );

        // Tamper with the proof
        if !proof.trace_commitment.is_empty() {
            // Modify first element of trace commitment
            let mut tampered_commitment = ArrayTrait::new();
            tampered_commitment.append(0x999999999999999); // Invalid value
            for i in 1..proof.trace_commitment.len() {
                tampered_commitment.append(*proof.trace_commitment.at(i));
            }
            proof.trace_commitment = tampered_commitment;
        }

        // Verify tampered proof
        let verification_result = SignatureVerificationSTARK::verify_stark_proof(
            @public_input,
            proof
        );

        assert(!verification_result, 'Tampered proof was accepted');
    }

    #[test]
    fn test_different_message_rejection() {
        // Create initial test inputs
        let public_input = create_test_public_input();
        let private_input = create_test_private_input();

        // Generate proof with original message
        let proof = SignatureVerificationSTARK::generate_stark_proof(
            @public_input,
            private_input
        );

        // Create modified public input with different message
        let modified_public_input = PublicInput {
            message_hash: 0x999999999999999, // Different message hash
            public_key: public_input.public_key,
            signature: public_input.signature
        };

        // Verify proof with modified message
        let verification_result = SignatureVerificationSTARK::verify_stark_proof(
            @modified_public_input,
            proof
        );

        assert(!verification_result, 'Proof accepted for different message');
    }
}
