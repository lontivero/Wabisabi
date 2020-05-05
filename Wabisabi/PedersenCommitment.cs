using System;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public readonly struct PedersenCommitment
	{
		private static readonly GE G = GEs.Gg;
		private static readonly GE H = GEs.Gh;

		// Secret blinding factor.
		private readonly Scalar x;
		// Amount being committed to.
		private readonly Scalar a;
		private readonly bool preserveSecrets;
		private readonly GE commitment;

		public PedersenCommitment(Scalar blindingFactor, Scalar value)
		{
			if (blindingFactor.IsZero) throw new ArgumentOutOfRangeException(nameof(blindingFactor));
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

		public bool Verify(Scalar blindingFactor, Scalar value)
		{
			var commitment = new PedersenCommitment(blindingFactor, value);
			return this == commitment;
		}

		public static PedersenCommitment operator + (PedersenCommitment c1, PedersenCommitment c2)
		{
			// Pedersen commitments are additively homomorphic.
			// So Commit(x1, a1) + Commit(x2, a2) = Commit((x1 + x2), (a1 + a2))

			// Preserve secrets in the result if they are known.
			if (c1.preserveSecrets && c2.preserveSecrets)
			{
				return new PedersenCommitment(c1.x.Add(c2.x), c1.a.Add(c2.a));
			}
			// The secret values were not available, just give back the summed commitment.
			return new PedersenCommitment(c1.commitment.ToGroupElementJacobian().Add(c2.commitment).ToGroupElement());
		}

		public static PedersenCommitment operator - (PedersenCommitment c1, PedersenCommitment c2)
		{
			// Preserve secrets in the result if they are known.
			if (c1.preserveSecrets && c2.preserveSecrets)
			{
				return new PedersenCommitment(c1.x.Add(c2.x.Negate()), c1.a.Add(c2.a.Negate()));
			}
			// The secret values were not available, just give back the summed commitment.
			return new PedersenCommitment(c1.commitment.ToGroupElementJacobian().Add(c2.commitment.Negate()).ToGroupElement());
		}

		public static bool operator == (PedersenCommitment c1, PedersenCommitment c2) => c1.Equals(c2);
		public static bool operator != (PedersenCommitment c1, PedersenCommitment c2)=> !c1.Equals(c2);

		public readonly override bool Equals(object obj)
		{
			if (obj is PedersenCommitment other)
			{
				return this.Equals(other);
			}
			return false;
		}

		public bool Equals(PedersenCommitment other)
		{
			// Using & because we need constant-time comparisons
			return (this.commitment.x == other.commitment.x)
				 & (this.commitment.y == other.commitment.y);
		}
	}
}
