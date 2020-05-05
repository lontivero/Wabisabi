using System;
using System.Linq;
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
			var commitToAliceBalance = new PedersenCommitment(aliceBalance, aliceBlindinFactor);

			var bobBalance   = new Scalar( 78_000u);
			var bobBlindinFactor = new Scalar(987654321);
			var commitToBobBalance = new PedersenCommitment(bobBalance, bobBlindinFactor);

			var valueTransferredToBob = new Scalar(25_000);
			var valueTransferredBlindinFactor = new Scalar(8050);
			var commitToTransferredValue = new PedersenCommitment(valueTransferredToBob, valueTransferredBlindinFactor);

			var aliceNewBalance = aliceBalance.Add(valueTransferredToBob.Negate());
			var bobNewBalance = bobBalance.Add(valueTransferredToBob);

			// Third party can do exactly the same operation but instead of doing it against the real values 
			// it does against the commitment.
			var commitToAliceNewBalance = commitToAliceBalance - commitToTransferredValue;
			var commitToBobNewBalance = commitToBobBalance + commitToTransferredValue;

			Assert.True(commitToAliceNewBalance.Verify(aliceNewBalance, aliceBlindinFactor.Add(valueTransferredBlindinFactor.Negate())));
			Assert.True(commitToBobNewBalance.Verify(bobNewBalance, bobBlindinFactor.Add(valueTransferredBlindinFactor)));
		}

		[Fact]
		public void ProductOfAttributes()
		{
			var k = 2;
			var v = Enumerable.Range(1, k).Select(x => Crypto.RandomScalarForValue()).ToArray();
			var r = Enumerable.Range(1, k).Select(x => Crypto.RandomScalar()).ToArray();
			var Mv = Enumerable.Range(0, k-1).Select(i => new GAttribute(v[i], r[i]));

			var Pi_Mv = Mv.Aggregate((Mvi, Mvj) => Mvi * Mvj);
			var v_sum = r.Aggregate((vi, vj)=> vi + vj);
			var r_sum = r.Aggregate((ri, rj)=> ri + rj);

			var C = new PedersenCommitment(r_sum, v_sum);

		//	Assert.Equal(C, Pi_Mv);
		}
	}
}