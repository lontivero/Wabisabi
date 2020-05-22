# Wabisabi protocol implementation

This is a one-file library that contains the functions needed to implement the Wabisabi protocol.

### Functional approach

The library consists in a set of pure functions instead of classes because the primitives are not "things" that need to communicate one each other by sending messages nor they need to keep internal state, in fact, we learnt that maintaining state creates expensive problems. Using a functional approach makes the code smaller, prevents sharing states and helps reviewers to understand the code better given cryptography is explained in terms of functions.

### Functions

#### Commitments

```c#
// Returns the Pedersen commitment of the value 'm' using the blinding factor 'r'. 
GroupElement Commit(Scalar m, Scalar r)

// Verifies the correctness of the opening of a commitment by checking Commit(m, r) == C
bool OpenCommit(GroupElement C, Scalar m, Scalar r)
```

**Example:**

```c#
var cr1 = RandomScalar();
var cr2 = RandomScalar();
var C10 = Commit(new Scalar(10), cr1);
var C35 = Commit(new Scalar(35), cr2);

Assert.True(OpenCommit(C10 + C35, new Scalar(45),  cr1 + cr2));
```

#### MAC


```c#
// Generates a secret key sk for MAC generations
ServerSecretKey GenServerSecretKey()

// Computes a MAC for Mv and Ms using the secret key sk 
MAC ComputeMAC(ServerSecretKey sk, Attribute attr)

// Verifies the 
bool VerifyMAC(ServerSecretKey sk, Attribute attr, MAC mac)
```


**Example:**

```c#
var r = RandomScalar();
var s = RandomScalar();
var serialNumber = RandomScalar();

var inputValueCommitment = Commit(new Scalar(2_000_000), r);
var serialNumberCommitment = Commit(serialNumber, s);

var attribute = new Attribute(inputValueCommitment, serialNumberCommitment);

var sk = GenServerSecretKey();
var pk = ComputeServerPublicKey(sk);

var credential = ComputeMAC(sk, attribute);

var signingSecretKey = RandomScalar();
var randComm = RandomizeCommitments(signingKey, attributes, credentials);
var proofMAC = ProofOfKnowledgeMAC(signingKey, credential.t, pk.I, randComm.Cx0);

var signingPublicKey = VerifyCredential(sk, randComm);

Assert.True(VerifyZeroKnowledgeProofMAC(signingPublicKey, randComm.Cx1, pk.I, randComm.Cx0, proofMAC));
```
