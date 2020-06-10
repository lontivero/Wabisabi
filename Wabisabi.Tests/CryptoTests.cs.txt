using System;
using System.Collections.Generic;
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
			var commitToAliceBalance = Commit(aliceBlindinFactor, aliceBalance);

			var bobBalance   = new Scalar( 78_000u);
			var bobBlindinFactor = new Scalar(987654321);
			var commitToBobBalance = Commit(bobBlindinFactor, bobBalance);

			var valueTransferredToBob = new Scalar(25_000);
			var valueTransferredBlindinFactor = new Scalar(8050);
			var commitToTransferredValue = Commit(valueTransferredBlindinFactor, valueTransferredToBob);

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
			var attr = WithRandomFactor(Commit);

			var a = attr(new Scalar(1_234_567));
			var b = attr(new Scalar(7_564_321));

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
			var Mv = Commit(new Scalar( 21_000_000), RandomScalar());
			var Ms = Commit(Crypto.RandomScalar(), Crypto.RandomScalar());
			var attribute = new Attribute(Mv, Ms);
			var commutedAttribute = new Attribute(Ms, Mv);

			var mac = ComputeMAC(sk, attribute);

			Assert.True(VerifyMAC(sk, attribute, mac));
			Assert.False(VerifyMAC(sk, commutedAttribute, mac));
		}

		private static Scalar RandomScalarForValue()
		{
			var ret = RandomScalar();
			ret.ShrInt(26, out ret);
			return ret;
		}

		/////////////////////////////////////////////////

		[Fact]
		public void xxxxxxxxxxxxx()
		{
			RangeProof(12345678);
		}

		private static Scalar[] BlindingVector(int nbits)
			=> Enumerable.Range(0, nbits).Select(_ => RandomScalar()).ToArray();

		private static string RangeProof(uint value)
		{
			var b = RandomScalar();
			var V = Commit(new Scalar(value), b);
			var aL = Vectorize(value);
			var aR = Substract(aL, Vectorize(uint.MaxValue));
			Assert.Equal(Vectorize(0), Hadamard(aL, aR));
			Assert.Equal(value, InnerProduct(aL, PowerVector(2)));

			return null;
		}

		private static int[] Vectorize(uint value)
		{
			var buffer = new int[32];
			var pos = buffer.Length - 1;
			while (value > 0)
			{
				buffer[pos] = (int)value % 2;
				pos--;
				value /= 2;
			}
			return buffer;
		}

		private static int[] Substract(int[] v1, int[] v2)
			=> Enumerable.Zip(v1, v2).Select( t => t.First - t.Second).ToArray();

		private static int[] Hadamard(int[] v1, int[] v2)
			=> Enumerable.Zip(v1, v2).Select( t => (t.First * t.Second) % (8 * sizeof(uint)) ).ToArray();

		private static uint InnerProduct(int[] v1, int[] v2)
			=> (uint)Enumerable.Zip(v1, v2).Select( t => (t.First * t.Second)).Sum();

		private static int[] PowerVector(int p)
			=> Enumerable.Range(0, (8 * sizeof(uint))).Select(x => (int)Math.Pow(p, x)).Reverse().ToArray();

	}
}