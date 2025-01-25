// signature_verifier.cairo
use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;
use starknet::ContractAddress;

#[starknet::contract]
mod SignatureVerifier {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_signature(
        self: @ContractState,
        signature: felt252,
        transaction_hash: felt252,
        public_key: felt252
    ) -> bool {
        // Initialize Poseidon hash state
        let mut hash_state = PoseidonTrait::new();
        
        // Update hash state with inputs
        hash_state.update(transaction_hash);
        hash_state.update(public_key);
        
        // Compute final hash
        let expected_signature = hash_state.finalize();
        
        // Verify signature matches expected
        signature == expected_signature
    }

    #[external(v0)]
    fn compute_hash(
        self: @ContractState, 
        data: Array<felt252>
    ) -> felt252 {
        let mut hash_state = PoseidonTrait::new();
        let len = data.len();
        let mut i = 0;
        
        // Update hash state with all elements
        loop {
            if i >= len {
                break;
            }
            hash_state.update(*data[i]);
            i += 1;
        };
        
        hash_state.finalize()
    }
}

// Tests module
#[cfg(test)]
mod tests {
    use super::SignatureVerifier;
    use starknet::testing::set_caller_address;
    
    #[test]
    fn test_valid_signature() {
        // Test data
        let transaction_hash = 123456789;
        let public_key = 987654321;
        let signature = 29829348; // TODO: Generate valid test signature
        
        let result = SignatureVerifier::verify_signature(
            signature,
            transaction_hash,
            public_key
        );
        
        assert(result, 'Signature verification failed');
    }
    
    #[test]
    fn test_invalid_signature() {
        // Test data
        let transaction_hash = 123456789;
        let public_key = 987654321;
        let invalid_signature = 111111111;
        
        let result = SignatureVerifier::verify_signature(
            invalid_signature,
            transaction_hash,
            public_key
        );
        
        assert(!result, 'Invalid signature was accepted');
    }
}