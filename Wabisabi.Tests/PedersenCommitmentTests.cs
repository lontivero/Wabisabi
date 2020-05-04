using System;
using NBitcoin.Secp256k1;
using Xunit;

namespace Wabisabi.Tests
{
	public class PedersenCommitmentTests
	{
		[Fact]
		public void ThirdPartyCanVerifyTotalMoneyInSystem()
		{
			// Alice has 163,000b in her balance and Bob has 78,000 in his balance
			// Alice wants to send 25,000 to Bob
			// A third party who cannot see the real balances should be able verify that
			// the total balance in the system didn't change (no money created from thin air)
			var aliceBalance = new Scalar(163_000u);
			var aliceBlindinFactor = new Scalar(123456);
			var commitToAliceBalance = new PedersenCommitment(aliceBlindinFactor, aliceBalance);

			var bobBalance   = new Scalar( 78_000u);
			var bobBlindinFactor = new Scalar(987654321);
			var commitToBobBalance = new PedersenCommitment(bobBlindinFactor, bobBalance);

			var valueTransferredToBob = new Scalar(25_000);
			var valueTransferredBlindinFactor = new Scalar(8050);
			var commitToTransferredValue = new PedersenCommitment(valueTransferredBlindinFactor, valueTransferredToBob);

			var aliceNewBalance = aliceBalance.Add(valueTransferredToBob.Negate());
			var bobNewBalance = bobBalance.Add(valueTransferredToBob);

			// Third party can do exactly the same operation but instead of doing it against the real values 
			// it does against the commitment.
			var commitToAliceNewBalance = commitToAliceBalance - commitToTransferredValue;
			var commitToBobNewBalance = commitToBobBalance + commitToTransferredValue;

			Assert.True(commitToAliceNewBalance.Verify(aliceBlindinFactor.Add(valueTransferredBlindinFactor.Negate()), aliceNewBalance));
			Assert.True(commitToBobNewBalance.Verify(bobBlindinFactor.Add(valueTransferredBlindinFactor), bobNewBalance));
		}
	}
}