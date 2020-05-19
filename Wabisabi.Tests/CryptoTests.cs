using System;
using System.Linq;
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

			var v_sum = v.Aggregate((vi, vj)=> vi + vj);
			var r_sum = r.Aggregate((ri, rj)=> ri + rj);
			var Pi_Mv = Mv.Aggregate((Mvi, Mvj) => Mvi + Mvj);
			var C = Commit(v_sum, r_sum);

			Assert.True(C == Pi_Mv);
		}

		[Fact]
		public void CanProduceAndVerifyMAC()
		{
			var sk = GenMACKey();
			var Mv = Commit(new Scalar( 21_000_000), RandomScalar());
			var Ms = Commit(Crypto.RandomScalar(), Crypto.RandomScalar());

			var mac = MAC(sk, Mv, Ms);

			Assert.True(VerifyMAC(sk, Mv, Ms, mac));
			Assert.False(VerifyMAC(sk, Ms, Mv, mac));
		}


		[Fact]
		public void Protocol()
		{
			///////// ALICE ------------>>>>>
			// Alice wants to participate with one coin of 5_200_000 satoshies and get 
			// (2 x 2_000_000) + (1 x 1_000_000) + (1 x 200_000)
			var r = GenerateRandomNumbers(4);
			var s = GenerateRandomNumbers(4);
			var Mv0 = Commit(new Scalar(2_000_000), r[0]);
			var Mv1 = Commit(new Scalar(2_000_000), r[1]);
			var Mv2 = Commit(new Scalar(1_000_000), r[2]);
			var Mv3 = Commit(new Scalar(  200_000), r[3]);

			var serialNumbers = GenerateRandomNumbers(4);
			var Ms0 = Commit(serialNumbers[0], s[0]);
			var Ms1 = Commit(serialNumbers[1], s[1]);
			var Ms2 = Commit(serialNumbers[2], s[2]);
			var Ms3 = Commit(serialNumbers[3], s[3]);

			// this is what we send to the coordinator
			var inputRegistrationRequest = new { 
				Amount = new Scalar(5_200_000),
				Attributes = new (GroupElement Mv, GroupElement Ms)[]{ 
					( Mv0, Ms0 ),
					( Mv1, Ms1 ),
					( Mv2, Ms2 ),
					( Mv3, Ms3 )
				},
				RangeProofs = new byte[0],
				SumProofs = Sum(r)
			};
				
			///////// <<<<<------- Coordinator
			var sk = GenMACKey();
			var iparams = ComputeIParams(sk);
			var ireq = inputRegistrationRequest;
			var attrs = ireq.Attributes;

			// Checks the amounts
			var sumAmountCommitment = attrs.Select(x => x.Mv).Aggregate((Mvi, Mvj) => Mvi + Mvj);
			var CommitmentSumAmount = Commit(ireq.Amount, ireq.SumProofs);
			Assert.Equal(sumAmountCommitment, CommitmentSumAmount);

			// Checks the amount ranges..... coming soon

			var credential0 = MAC(sk, attrs[0].Mv, attrs[0].Ms);
			var credential1 = MAC(sk, attrs[1].Mv, attrs[1].Ms);
			var credential2 = MAC(sk, attrs[2].Mv, attrs[2].Ms);
			var credential3 = MAC(sk, attrs[3].Mv, attrs[3].Ms);

			var inputRegistrationResponse = new {
				iParams = iparams,
				Credentials = new[]{
					credential0,
					credential1,
					credential2,
					credential3
				}
			};


			///////// Bob ------------>>>>>
			// Receives the credentials and
			var ires = inputRegistrationResponse;  
			var z = GenerateRandomNumbers(4);
			var rc0 = RandomizedCommitments(z[0], Mv0, Ms0, ires.Credentials[0]);
			var rc1 = RandomizedCommitments(z[1], Mv1, Ms1, ires.Credentials[1]);
			var rc2 = RandomizedCommitments(z[2], Mv2, Ms2, ires.Credentials[2]);
			var rc3 = RandomizedCommitments(z[3], Mv3, Ms3, ires.Credentials[3]);

			var ProofKnowledgeMAC = ProofGeneratorFor(ires.iParams.I);
			var pmac0 = ProofKnowledgeMAC(z[0]);
			var pmac1 = ProofKnowledgeMAC(z[1]);
			var pmac2 = ProofKnowledgeMAC(z[2]);
			var pmac3 = ProofKnowledgeMAC(z[3]);

			var outputRegistrationRequest = new {
				XX = new [] {
					(rc0.Cx0, rc0.Cx1, rc0.CV, rc0.Cv, rc0.Cs, Proof: pmac0),
					(rc1.Cx0, rc1.Cx1, rc1.CV, rc1.Cv, rc1.Cs, Proof: pmac1),
					(rc2.Cx0, rc2.Cx1, rc2.CV, rc2.Cv, rc2.Cs, Proof: pmac2),
					(rc3.Cx0, rc3.Cx1, rc3.CV, rc3.Cv, rc3.Cs, Proof: pmac3)
				},
				OverSpendingPreventionProof = (SumZ: Sum(z), SumR: Sum(r) ),
				VOut = new Scalar(5_200_000)
			};

			///////// <<<<<------- Coordinator
			var oreq = outputRegistrationRequest;

			var (c0, c1, c2, c3) = (oreq.XX[0], oreq.XX[1], oreq.XX[2], oreq.XX[3]);
			var Z0 = c0.CV + ((sk.w * Generators.Gw) + (sk.x0 * c0.Cx0)  + (sk.x1 * c0.Cx1)  + (sk.yv * c0.Cv)  + (sk.ys * c0.Cs)).Negate(); // create a function for this
			var Z1 = c1.CV + ((sk.w * Generators.Gw) + (sk.x0 * c1.Cx0)  + (sk.x1 * c1.Cx1)  + (sk.yv * c1.Cv)  + (sk.ys * c1.Cs)).Negate();
			var Z2 = c2.CV + ((sk.w * Generators.Gw) + (sk.x0 * c2.Cx0)  + (sk.x1 * c2.Cx1)  + (sk.yv * c2.Cv)  + (sk.ys * c2.Cs)).Negate();
			var Z3 = c3.CV + ((sk.w * Generators.Gw) + (sk.x0 * c3.Cx0)  + (sk.x1 * c3.Cx1)  + (sk.yv * c3.Cv)  + (sk.ys * c3.Cs)).Negate();

			// Check Bob has valid credentials
			Assert.Equal(c0.Proof, Z0);
			Assert.Equal(c1.Proof, Z1);
			Assert.Equal(c2.Proof, Z2);
			Assert.Equal(c3.Proof, Z3);

			// Check over-spending 

			var sumAmountCommitment2 = c0.Cv + c1.Cv + c2.Cv + c3.Cv;

			var commitmentSumAmount2 = oreq.OverSpendingPreventionProof.SumZ * Generators.Gv 
									 + Commit(oreq.VOut, oreq.OverSpendingPreventionProof.SumR);


			Assert.Equal(sumAmountCommitment2, commitmentSumAmount2);
		}


		private static Scalar[] GenerateRandomNumbers(int n)
			=> Enumerable.Range(0, n).Select(_=> RandomScalar()).ToArray();

		private static Scalar RandomScalarForValue()
		{
			var ret = RandomScalar();
			ret.ShrInt(26, out ret);
			return ret;
		}

		private static Scalar Sum(Scalar[] me)
			=> me.Aggregate((s1, s2) => s1 + s2);
	}
}