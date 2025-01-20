// Import the Poseidon hash function
use starkware.crypto.signature.poseidon_hash::poseidon_hash;

// Function to generate the proof
#[derive(Debug, PartialEq)]
fn generate_proof(
    signature: felt252,          
    transaction_hash: felt252,   
    public_key: felt252
) -> felt252 {
    // Compute the expected signature
    let computed_signature = poseidon_hash([public_key, transaction_hash]);

    // Verify that the provided signature matches the computed one
    assert computed_signature == signature;

    // Return 1 to indicate success
    return 1;
}

// Function to verify the proof
#[derive(Debug, PartialEq)]
fn verify_proof(
    proof: felt252,              
    transaction_hash: felt252,   
    public_key: felt252          
) -> felt252 {
    // Recompute the expected proof from public inputs
    let expected_proof = poseidon_hash([public_key, transaction_hash]);

    // Verify that the provided proof matches the expected proof
    assert proof == expected_proof;

    // Return 1 to indicate successful verification
    return 1;
}

//test