using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public class GAttribute : Comm
	{
		public GAttribute(ulong attr)
			:  this(new Scalar((uint)(attr >> 32), (uint)attr, 0, 0 ,0 , 0, 0, 0  ))
		{
		}

		public GAttribute(Scalar attr)
			:  this(Crypto.RandomScalar(), attr)
		{
		}

		public GAttribute(Scalar blindingFactor, Scalar attr)
			: base(blindingFactor, attr)
		{
		}

		public static GAttribute operator + (GAttribute a, GAttribute b)
		{
			var t = (Comm)a + (Comm)b;
			return new GAttribute(t.BlindingFactor, t.Value);
		}
	}
}
