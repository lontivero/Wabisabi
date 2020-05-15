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
(Scalar x0, Scalar x1, Scalar y0, Scalar y1) GenMACKey()

// Computes a MAC for Mv and Ms using the secret key sk 
(Scalar t, GroupElement U, GroupElement V) MAC((Scalar x0, Scalar x1, Scalar y0, Scalar y1) sk, GroupElement Mv, GroupElement Ms)

// Verifies the 
bool VerifyMAC((Scalar, Scalar, Scalar, Scalar) sk, GroupElement Mv, GroupElement Ms, (Scalar t, GroupElement U, GroupElement V) mac)
```
**Example:**

```c#
var sk = GenMACKey();
var Mv = Commit(new Scalar( 21_000_000), RandomScalar());
var Ms = Commit(Crypto.RandomScalar(), Crypto.RandomScalar());

var mac = MAC(sk, Mv, Ms);

Assert.True(VerifyMAC(sk, Mv, Ms, mac));
Assert.False(VerifyMAC(sk, Ms, Mv, mac));
```
