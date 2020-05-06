using System;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public class MAC : IEquatable<MAC>
	{
		public readonly Scalar t;
		public readonly GE U;
		public readonly GE V;

		public MAC(Scalar t, GE U, GE V)
		{
			this.t = t;
			this.U = U;
			this.V = V;
		}

		public static MAC Compute((Scalar x0, Scalar x1) sk, IGroupElement M)
		{
			var u = Crypto.RandomScalar();
			var U = (u * EC.G).ToGroupElement();
			return Compute(sk, M, Crypto.RandomScalar(), U);
		}

		internal static MAC Compute((Scalar x0, Scalar x1) sk, IGroupElement M, Scalar t, GE U)
		{
			var V = (sk.x0 + sk.x1 * t) * U;
			V = V.AddVariable(M.ToGroupElement(), out _);
			return new MAC(t, U, V.ToGroupElement());
		}

		public static bool Verify((Scalar x0, Scalar x1) sk, IGroupElement M, MAC mac)
		{
			return Compute(sk, M, mac.t, mac.U) == mac;
		}

		public static bool operator == (MAC m1, MAC m2) => m1.Equals(m2);
		public static bool operator != (MAC m1, MAC m2)=> !m1.Equals(m2);

		public override bool Equals(object obj)
		{
			if (obj is MAC other)
			{
				return this.Equals(other);
			}
			return false;
		}

		public bool Equals(MAC other)
		{
			return this.t == other.t 
				 & (this.U.x == other.U.x & this.U.y == other.U.y)
				 & (this.V.x == other.V.x & this.V.y == other.V.y);
		}

		public override int GetHashCode()
		{
			return HashCode.Combine(t, U, V);
		}
	}
}