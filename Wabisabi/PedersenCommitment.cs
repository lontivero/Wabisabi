using System;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public interface IGroupElement
	{
		GE ToGroupElement();
	}

	public class PedersenCommitment : IGroupElement, IEquatable<PedersenCommitment>
	{
		private static readonly GE G = GEs.Gg;
		private static readonly GE H = GEs.Gh;


		// Secret blinding factor.
		public Scalar BlindingFactor { get; }
		// Amount being committed to.
		public Scalar Value { get; }
		private readonly bool _preserveSecrets;
		private readonly GE _commitment;

		public PedersenCommitment(Scalar blindingFactor, Scalar value)
		{
			this.BlindingFactor = blindingFactor;
			this.Value = value;
			this._preserveSecrets = true;

			var x = blindingFactor;
			var a = value;
			this._commitment = (x * G).AddVariable(a * H, out _).ToGroupElement();
		}

		private PedersenCommitment(GE commitment)
		{
			// Only the commitment is known, this is how the commitment will be seen by most users.
			this._preserveSecrets = false;
			this._commitment = commitment;
			this.BlindingFactor = Scalar.Zero;
			this.Value = Scalar.Zero;
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
			if (c1._preserveSecrets && c2._preserveSecrets)
			{
				return new PedersenCommitment(c1.BlindingFactor.Add(c2.BlindingFactor), c1.Value.Add(c2.Value));
			}
			// The secret values were not available, just give back the summed commitment.
			return new PedersenCommitment(c1._commitment.ToGroupElementJacobian().Add(c2._commitment).ToGroupElement());
		}

		public static PedersenCommitment operator - (PedersenCommitment c1, PedersenCommitment c2)
		{
			return c1 + c2.Negate();
		}

		public PedersenCommitment Negate()
		{
			return _preserveSecrets
				? new PedersenCommitment(BlindingFactor.Negate(), Value.Negate())
				: new PedersenCommitment(_commitment.Negate());
		}

		public GE ToGroupElement()
		{
			return _commitment;
		}

		public static bool operator == (PedersenCommitment c1, PedersenCommitment c2) => c1.Equals(c2);
		public static bool operator != (PedersenCommitment c1, PedersenCommitment c2)=> !c1.Equals(c2);

		public override bool Equals(object obj)
		{
			if (obj is PedersenCommitment other)
			{
				return this.Equals(other);
			}
			return false;
		}

		public bool Equals(PedersenCommitment other)
		{
			return (this._commitment.IsInfinity && other._commitment.IsInfinity)
			 	|| (this._commitment.x == other._commitment.x && this._commitment.y == other._commitment.y);
		}

		public override int GetHashCode()
		{
			return HashCode.Combine(BlindingFactor, Value, _preserveSecrets, _commitment);
		}
	}
}