using NBitcoin.Secp256k1;

namespace Wabisabi
{
    public readonly partial struct GAttribute
	{
		private readonly PedersenCommitment pe;
		private readonly Scalar blindingFactor;

		public GAttribute(Scalar attr)
			:  this(attr, Crypto.RandomScalar())
		{
		}

		public GAttribute(Scalar attr, Scalar blindingFactor)
		{
			this.blindingFactor = blindingFactor;
			this.pe = new PedersenCommitment(attr, blindingFactor);
		}

		public static GAttribute operator * (GAttribute a, GAttribute b)
		{
			var t = a.pe + b.pe;
			return new GAttribute(t.a, t.x);
		}
	}
}
