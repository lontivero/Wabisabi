using System;
using System.Linq;
using System.Security.Cryptography;
using NBitcoin.Secp256k1;
using Xunit;
using static Wabisabi.Crypto;

namespace Wabisabi.Tests
{
	public class CryptoTests
	{
		[Fact]
		public void Comparison()
		{
			var pedersenCommitment = WithRandomFactor(Commit);

			var pe = pedersenCommitment(new Scalar(15_000));
			var zero1 = pe + pe.Negate();

			var pe2 = pedersenCommitment(new Scalar(57_000));
			var zero2 = pe2 + pe2.Negate();

			Assert.Equal(pe, pe);
			Assert.Equal(zero1, zero1);
			Assert.NotEqual(pe, zero1);
			Assert.NotEqual(zero1, pe);

			Assert.Equal(pe, pe + zero1);
			Assert.Equal(pe, pe + zero1.Negate());

			Assert.Equal(pe, zero1 + pe);
			Assert.Equal(pe.Negate(), zero1 + pe.Negate());

			Assert.Equal(zero2, zero1);
			Assert.Equal(zero1, zero2);

			Assert.Equal(zero1, zero1 + zero2.Negate());
			Assert.Equal(zero1, zero2 + zero1.Negate());
			Assert.Equal(zero2, zero1 + zero2.Negate());
			Assert.Equal(zero2, zero2 + zero1.Negate());

			Assert.Equal(zero1, zero1 + zero2);
			Assert.Equal(zero1, zero2 + zero1);
			Assert.Equal(zero2, zero1 + zero2);
			Assert.Equal(zero2, zero2 + zero1);
		}

		[Fact]
		public void ThirdPartyCanVerifyTotalMoneyInSystem()
		{
			// Alice has 163,000b in her balance and Bob has 78,000 in his balance
			// Alice wants to send 25,000 to Bob
			// A third party who cannot see the real balances should be able verify that
			// the total balance in the system didn't change (no money created from thin air)
			var aliceBalance = new Scalar(163_000u);
			var aliceBlindinFactor = new Scalar(123456);
			var commitToAliceBalance = Commit(aliceBalance, aliceBlindinFactor);

			var bobBalance   = new Scalar( 78_000u);
			var bobBlindinFactor = new Scalar(987654321);
			var commitToBobBalance = Commit(bobBalance, bobBlindinFactor);

			var valueTransferredToBob = new Scalar(25_000);
			var valueTransferredBlindinFactor = new Scalar(8050);
			var commitToTransferredValue = Commit(valueTransferredToBob, valueTransferredBlindinFactor);

			var aliceNewBalance = aliceBalance.Add(valueTransferredToBob.Negate());
			var bobNewBalance = bobBalance.Add(valueTransferredToBob);

			// Third party can do exactly the same operation but instead of doing it against the real values 
			// it does against the commitment.
			var commitToAliceNewBalance = commitToAliceBalance + commitToTransferredValue.Negate();
			var commitToBobNewBalance = commitToBobBalance + commitToTransferredValue;

			Assert.True(OpenCommit(commitToAliceNewBalance, aliceNewBalance, aliceBlindinFactor + valueTransferredBlindinFactor.Negate()));
			Assert.True(OpenCommit(commitToBobNewBalance, bobNewBalance, bobBlindinFactor + valueTransferredBlindinFactor ));
		}

		[Fact]
		public void AttributesAreCommutative()
		{
			var (a, _) = Attribute(new Scalar(1_234_567));
			var (b, _) = Attribute(new Scalar(7_564_321));

			Assert.Equal((a+b), b+a);
		}

		[Fact]
		public void ProofAttributeSumOfValueEqual()
		{
			var k = 10;
			var v = Enumerable.Range(1, k).Select(i => RandomScalarForValue()).ToArray();
			var r = Enumerable.Range(1, k).Select(i => RandomScalar()).ToArray();
			var Mv = Enumerable.Range(0, k).Select(i => Commit(v[i], r[i])).ToArray();

			Assert.Equal(Commit(Sum(v), Sum(r)), Sum(Mv));
		}

		[Fact]
		public void CanProduceAndVerifyMAC()
		{
			var sk = GenServerSecretKey();
			var (attr, _) = Attribute(new Scalar( 21_000_000));

			var mac = ComputeMAC(sk, attr);

			Assert.True(VerifyMAC(sk, attr, mac));
		}

		[Fact]
		public void CanProduceAndVerifyProofOfRepresentation()
		{
			var sk = GenServerSecretKey();
			var (attr, _) = Attribute(new Scalar( 21_000_000));

			var w0 = new Scalar(11);
			var w1 = new Scalar(17);

			var C = Commit(w0, w1);

			var proof = ProofOfKnowledge(new[]{ w0, w1 }, new[]{ Generators.Gg, Generators.Gh});
			Assert.True(VerifyProofOfKnowledge(new[] { C }, new[]{ Generators.Gg, Generators.Gh}, proof));
		}


		[Fact]

		private static Scalar RandomScalarForValue()
		{
			var ret = RandomScalar();
			ret.ShrInt(26, out ret);
			return ret;
		}
	}
}