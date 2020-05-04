using System;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public struct PedersenCommitment
	{
		// This generator should be past in the .ctor
		private static readonly GE G = EC.G;

		// Secret blinding factor.
		private readonly Scalar x;

		// Amount being committed to.
		private readonly Scalar a;

		// Generator point of the group. This generator should be past in the .ctor
		// X coordinate of 'H'.
		private static readonly FE H_x = new FE(
			new byte[]
			{
				0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
				0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0
			});

		// Y coordinate of 'H'.
		private static readonly FE H_y = new FE(
			new byte[]
			{
				0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
				0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
			});

		// H is an additional generator point for the group.
		// It can be calculated as follow:
		// H = Secp256k1.Curve.DecodePoint(new[] { (byte)0x02 }.Concat(Hashes.SHA256(G.GetEncoded(false))));
		// This is unrelated to the cofactor 'H' of the secp256k1 curve.
		private static readonly GE H = new GE(H_x, H_y);

		private bool preserveSecrets;
		// The actual commitment, which is simply a point on the secp256k1 curve.
		private readonly GE commitment;

		public PedersenCommitment(Scalar blindingFactor, Scalar value)
		{
			this.x = blindingFactor;
			this.a = value;
			this.preserveSecrets = true;

			// Pedersen commitment C = xG + aH
			this.commitment = (x * G).AddVariable(a * H, out _).ToGroupElement();
		}

		internal PedersenCommitment(GE commitment)
		{
			// Only the commitment is known, this is how the commitment will be seen by most users.
			this.preserveSecrets = false;
			this.commitment = commitment;
			this.x = Scalar.Zero;
			this.a = Scalar.Zero;
		}

		public static PedersenCommitment operator +(PedersenCommitment c1, PedersenCommitment c2)
		{
			// Pedersen commitments are additively homomorphic.
			// So Commit(x1, a1) + Commit(x2, a2) = Commit((x1 + x2), (a1 + a2))

			// Preserve secrets in the result if they are known.
			if (c1.preserveSecrets && c2.preserveSecrets)
				return new PedersenCommitment(c1.x.Add(c2.x), c1.a.Add(c2.a));

			// The secret values were not available, just give back the summed commitment.
			return new PedersenCommitment(c1.commitment.ToGroupElementJacobian().Add(c2.commitment).ToGroupElement());
		}

		public static PedersenCommitment operator +(Scalar n, PedersenCommitment c1)
		{
			if (!c1.preserveSecrets)
				throw new InvalidOperationException("Pedersen commitment's secret is not available");

			// Pedersen commitments are additively homomorphic.
			// Commit(x,r) + n = Commit(x + n,r)
			// Preserve secrets in the result if they are known.
				return new PedersenCommitment(c1.x.Add(n), c1.a);
		}

		public static PedersenCommitment operator -(PedersenCommitment c1, PedersenCommitment c2)
		{
			// Preserve secrets in the result if they are known.
			if (c1.preserveSecrets && c2.preserveSecrets)
				return new PedersenCommitment(c1.x.Add(c2.x.Negate()), c1.a.Add(c2.a.Negate()));

			// The secret values were not available, just give back the summed commitment.
			return new PedersenCommitment(c1.commitment.ToGroupElementJacobian().Add(c2.commitment.Negate()).ToGroupElement());
		}

		public bool Verify(Scalar blindingFactor, Scalar value)
		{
			var commitment = new PedersenCommitment(blindingFactor, value);
			return this == commitment;
		}

		public static bool operator ==(PedersenCommitment c1, PedersenCommitment c2)
		{
			return (c1.commitment.x == c2.commitment.x && c1.commitment.y == c2.commitment.y);
		}

		public static bool operator !=(PedersenCommitment c1, PedersenCommitment c2)
		{
			return !(c1.commitment.x == c2.commitment.x && c1.commitment.y == c2.commitment.y);
		}
	}
}
