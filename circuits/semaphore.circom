pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./tree.circom";

// This template have the responsibility to create a secret that will
// be used to create the identity commitment. It receives two random 32-byte value
// inputs that are provided to  the main template as private inputs and hashes them.
template CalculateSecret() {
    // random 32-byte value provided by the user
    signal input identityNullifier;
    // random 32-byte value provided by the user
    signal input identityTrapdoor;

    // A hash
    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== identityNullifier;
    poseidon.inputs[1] <== identityTrapdoor;

    out <== poseidon.out;
}

// This template has the responsibility to calculate the identity commitment.
// It receives one secret input that is calculated based on identityNullifier, identityTrapdoor
// provided by the user.
template CalculateIdentityCommitment() {
    // Hash of identityNullifier and identityTrapdoor calculated with the template CalculateSecret
    signal input secret;

    // A hash
    signal output out;

    component poseidon = Poseidon(1);

    poseidon.inputs[0] <== secret;

    out <== poseidon.out;
}

// The circuit hashes the identity nullifier and the external nullifier.
//  The it checks that it matches the given nullifiers hash. 
template CalculateNullifierHash() {
    signal input externalNullifier;
    signal input identityNullifier;

    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== externalNullifier;
    poseidon.inputs[1] <== identityNullifier;

    out <== poseidon.out;
}

// nLevels must be < 32.
template Semaphore(nLevels) {
    //  a random 32-byte value which the user should save
    signal input identityNullifier;

    //  a random 32-byte value which the user should save
    signal input identityTrapdoor;

    //  the direction (0/1) per tree level corresponding to the Merkle path to the user's identity commitment.
    signal input treePathIndices[nLevels];

    // the values along the Merkle path to the user's identity commitment
    signal input treeSiblings[nLevels];

    //  the hash of the user's signal.
    signal input signalHash;

    // the 32-byte external nullifier.
    signal input externalNullifier;

    signal output root;

    // the hash of the identity nullifier and the external nullifier
    signal output nullifierHash;

    component calculateSecret = CalculateSecret();
    // set identityNullifier and identityTrapdoor with the values provided by the user to be hashed
    calculateSecret.identityNullifier <== identityNullifier;
    calculateSecret.identityTrapdoor <== identityTrapdoor;

    signal secret;
    //  set the signal secret with the hash of identityNullifier and identityTrapdoor
    secret <== calculateSecret.out;

    component calculateIdentityCommitment = CalculateIdentityCommitment();
    // set the secret to be hashed
    calculateIdentityCommitment.secret <== secret;

    component calculateNullifierHash = CalculateNullifierHash();
    calculateNullifierHash.externalNullifier <== externalNullifier;
    calculateNullifierHash.identityNullifier <== identityNullifier;

    // It then verifies the Merkle proof against 
    // the Merkle root and the identity commitment to guarantee that 
    // the identity commitment exists in the Merkle tree
    component inclusionProof = MerkleTreeInclusionProof(nLevels);
    inclusionProof.leaf <== calculateIdentityCommitment.out;

    for (var i = 0; i < nLevels; i++) {
        inclusionProof.siblings[i] <== treeSiblings[i];
        inclusionProof.pathIndices[i] <== treePathIndices[i];
    }

    root <== inclusionProof.root;

    // Dummy square to prevent tampering signalHash.
    // that guarantees the signal was truly broadcasted by the user who generated the proof.
    signal signalHashSquared;
    signalHashSquared <== signalHash * signalHash;

    //Guarantees that the signal was only broadcasted once
    nullifierHash <== calculateNullifierHash.out;
}

component main {public [signalHash, externalNullifier]} = Semaphore(20);
