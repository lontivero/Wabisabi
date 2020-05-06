using Xunit;

namespace Wabisabi.Tests
{
	public class MACTests
	{
		[Fact]
		public void CanProduceAndVerifyMACs()
		{
			var sk = (Crypto.RandomScalar(), Crypto.RandomScalar());

			var Mv = new GroupAttribute( 21_000_000);
			var Ms = new GroupAttribute(123_456_789);
			var mac = MAC.Compute(sk, Mv + Ms);

			Assert.True(MAC.Verify(sk, Mv + Ms, mac));
			Assert.True(MAC.Verify(sk, Ms + Mv, mac));
		}
	}
}
