using System.Linq;
using NBitcoin.Secp256k1;
using Xunit;

namespace Wabisabi.Tests
{
	public class MACTests
	{
		[Fact]
		public void x()
		{
			var w = Crypto.RandomScalar();
			var sk = (Crypto.RandomScalar(), Crypto.RandomScalar());

			var Mv = new GroupAttribute( 21_000_000);
			var Ms = new GroupAttribute(12_3456_789);
			var mac = MAC.Compute(w, sk, Mv + Ms);

			Assert.True(MAC.Verify(w, sk, Mv + Ms, mac));
		}
	}
}
