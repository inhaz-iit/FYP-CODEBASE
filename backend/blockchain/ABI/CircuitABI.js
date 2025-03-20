module.exports = CircuitABI = [
    {
        "type": "struct",
        "name": "circuit::SignatureVerificationSTARK::PublicInput",
        "members": [
            {
                "name": "message_hash",
                "type": "core::felt252"
            },
            {
                "name": "public_key",
                "type": "core::felt252"
            },
            {
                "name": "signature",
                "type": "core::felt252"
            }
        ]
    },
    {
        "type": "struct",
        "name": "circuit::SignatureVerificationSTARK::FRICommitment",
        "members": [
            {
                "name": "layers",
                "type": "core::array::Array::<core::array::Array::<core::felt252>>"
            },
            {
                "name": "final_polynomial",
                "type": "core::array::Array::<core::felt252>"
            }
        ]
    },
    {
        "type": "struct",
        "name": "circuit::SignatureVerificationSTARK::STARKProof",
        "members": [
            {
                "name": "trace_commitment",
                "type": "core::array::Array::<core::felt252>"
            },
            {
                "name": "trace_evaluation",
                "type": "core::array::Array::<core::felt252>"
            },
            {
                "name": "fri_commitments",
                "type": "circuit::SignatureVerificationSTARK::FRICommitment"
            },
            {
                "name": "low_degree_proof",
                "type": "core::array::Array::<core::felt252>"
            }
        ]
    },
    {
        "type": "function",
        "name": "generate_stark_proof",
        "inputs": [
            {
                "name": "public_input",
                "type": "circuit::SignatureVerificationSTARK::PublicInput"
            },
            {
                "name": "private_input",
                "type": "core::array::Array::<core::felt252>"
            }
        ],
        "outputs": [
            {
                "type": "circuit::SignatureVerificationSTARK::STARKProof"
            }
        ],
        "state_mutability": "view"
    },
    {
        "type": "enum",
        "name": "core::bool",
        "variants": [
            {
                "name": "False",
                "type": "()"
            },
            {
                "name": "True",
                "type": "()"
            }
        ]
    },
    {
        "type": "function",
        "name": "verify_stark_proof",
        "inputs": [
            {
                "name": "public_input",
                "type": "circuit::SignatureVerificationSTARK::PublicInput"
            },
            {
                "name": "proof",
                "type": "circuit::SignatureVerificationSTARK::STARKProof"
            }
        ],
        "outputs": [
            {
                "type": "core::bool"
            }
        ],
        "state_mutability": "view"
    },
    {
        "type": "event",
        "name": "circuit::SignatureVerificationSTARK::ProofGenerated",
        "kind": "struct",
        "members": [
            {
                "name": "proof_hash",
                "type": "core::felt252",
                "kind": "data"
            }
        ]
    },
    {
        "type": "event",
        "name": "circuit::SignatureVerificationSTARK::ProofVerified",
        "kind": "struct",
        "members": [
            {
                "name": "verification_result",
                "type": "core::bool",
                "kind": "data"
            }
        ]
    },
    {
        "type": "event",
        "name": "circuit::SignatureVerificationSTARK::Event",
        "kind": "enum",
        "variants": [
            {
                "name": "ProofGenerated",
                "type": "circuit::SignatureVerificationSTARK::ProofGenerated",
                "kind": "nested"
            },
            {
                "name": "ProofVerified",
                "type": "circuit::SignatureVerificationSTARK::ProofVerified",
                "kind": "nested"
            }
        ]
    }
];