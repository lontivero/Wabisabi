using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public class GroupAttribute : PedersenCommitment
	{
		public GroupAttribute(ulong attr)
			:  this(new Scalar((uint)(attr >> 32), (uint)attr, 0, 0 ,0 , 0, 0, 0  ))
		{
		}

		public GroupAttribute(Scalar attr)
			:  this(Crypto.RandomScalar(), attr)
		{
		}

		public GroupAttribute(Scalar blindingFactor, Scalar attr)
			: base(blindingFactor, attr)
		{
		}

		public static GroupAttribute operator + (GroupAttribute a, GroupAttribute b)
		{
			var t = (PedersenCommitment)a + (PedersenCommitment)b;
			return new GroupAttribute(t.BlindingFactor, t.Value);
		}
	}
}
