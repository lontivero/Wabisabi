using System;
using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public class AMAC
	{
		/*
			KeyGen:  choose random(x0,x1)∈Zq2, outputsk= (x0,x1).
			MAC(sk,m):  choose randomU∈G, outputσ= (U,Ux0+x1m).
			Verify(sk,(U,U′),m):  recomputeU′′=Ux0+x1m, output “valid” ifU′′=U′, and “invalid”otherwise.In [DKPW12] it i
		*/

		public readonly Scalar t;
		public readonly GE U;
		public readonly GE V;

		public AMAC(Scalar t, GE U, GE V)
		{
			this.t = t;
			this.U = U;
			this.V = V;
		}

/*
		public static AMAC Compute((Scalar x0, Scalar x1) sk, Scalar m)
		{
			var u = Crypto.RandomScalar();

			var U = (u * EC.G).ToGroupElement();
			var V =  ((sk.x0 + sk.x1 * m) * EC.G).ToGroupElement();
			return new AMAC(t, U, V);
		}
*/
	}
}