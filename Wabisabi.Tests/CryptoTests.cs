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


		[Fact]
		public void Protocol()
		{
			///////// ALICE ------------>>>>>
			// Alice wants to participate with one coin of 5_200_000 satoshies and get 
			// (2 x 2_000_000) + (1 x 1_000_000) + (1 x 200_000) but in this example we will finally register only one output 
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
			var attributes = new[] { 
				new Attribute( Mv0, Ms0 ),
				new Attribute( Mv1, Ms1 ),
				new Attribute( Mv2, Ms2 ),
				new Attribute( Mv3, Ms3 )
			};

			var inputRegistrationRequest = new { 
				Amount = new Scalar(5_200_000),
				Attributes = attributes,
				RangeProofs = new byte[0],  // not implemented yet
				ProofSum = Sum(r)
			};
				
			///////// <<<<<------- Coordinator
			var sk = GenServerSecretKey();  			// ServerSecretParams
			var iparams = ComputeServerPublicKey(sk);	// ServerPublicParams
			var ireq = inputRegistrationRequest;
			var attrs = ireq.Attributes;

			// Checks the amounts
			var sumAmountCommitment = Sum(attrs.Select(x => x.Mv));
			var CommitmentSumAmount = Commit(ireq.Amount, ireq.ProofSum);
			Assert.Equal(sumAmountCommitment, CommitmentSumAmount);

			// Checks the amount ranges..... coming soon

			// We must generate the proof of knowledge of the secret key here

			var credential0 = ComputeMAC(sk, attrs[0]);
			var credential1 = ComputeMAC(sk, attrs[1]);
			var credential2 = ComputeMAC(sk, attrs[2]);
			var credential3 = ComputeMAC(sk, attrs[3]);

			// This is what the coordinator responds to the client.
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
			// Receives the credentials and randomizes the commitments
			var ires = inputRegistrationResponse;  
			var z = GenerateRandomNumbers(4);
			var rc0 = RandomizeCommitments(z[0], attributes[0], ires.Credentials[0]);
			var rc1 = RandomizeCommitments(z[1], attributes[1], ires.Credentials[1]);
			var rc2 = RandomizeCommitments(z[2], attributes[2], ires.Credentials[2]);
			var rc3 = RandomizeCommitments(z[3], attributes[3], ires.Credentials[3]);

			var pkMAC0 = ProofOfKnowledgeMAC(z[0], ires.Credentials[0].t, iparams.I, rc0.Cx0);
			var pkMAC1 = ProofOfKnowledgeMAC(z[1], ires.Credentials[1].t, iparams.I, rc1.Cx0);
			var pkMAC2 = ProofOfKnowledgeMAC(z[2], ires.Credentials[2].t, iparams.I, rc2.Cx0);
			var pkMAC3 = ProofOfKnowledgeMAC(z[3], ires.Credentials[3].t, iparams.I, rc3.Cx0);

			var outputRegistrationRequest = new {
				ValidCredentialProof = new [] {
					(RandomizedCredential: rc0, Proof: pkMAC0),  // how should I call these records? ValidCredentialProof?
					(RandomizedCredential: rc1, Proof: pkMAC1),
					(RandomizedCredential: rc2, Proof: pkMAC2),
					(RandomizedCredential: rc3, Proof: pkMAC3)
				},
				OverSpendingPreventionProof = (SumZ: Sum(z), SumR: Sum(r) ),
				OutputValue = new Scalar(5_200_000)
			};

			///////// <<<<<------- Coordinator
			var oreq = outputRegistrationRequest;

			var (c0, c1, c2, c3) = (oreq.ValidCredentialProof[0], oreq.ValidCredentialProof[1], oreq.ValidCredentialProof[2], oreq.ValidCredentialProof[3]);
			var Z0 = VerifyCredential(sk, c0.RandomizedCredential);
			var Z1 = VerifyCredential(sk, c1.RandomizedCredential);
			var Z2 = VerifyCredential(sk, c2.RandomizedCredential);
			var Z3 = VerifyCredential(sk, c3.RandomizedCredential);

			// Check Bob has valid credentials

			Assert.True(VerifyZeroKnowledgeProofMAC(Z0, c0.RandomizedCredential.Cx1, iparams.I, c0.RandomizedCredential.Cx0, c0.Proof));
			Assert.True(VerifyZeroKnowledgeProofMAC(Z1, c1.RandomizedCredential.Cx1, iparams.I, c1.RandomizedCredential.Cx0, c1.Proof));
			Assert.True(VerifyZeroKnowledgeProofMAC(Z2, c2.RandomizedCredential.Cx1, iparams.I, c2.RandomizedCredential.Cx0, c2.Proof));
			Assert.True(VerifyZeroKnowledgeProofMAC(Z3, c3.RandomizedCredential.Cx1, iparams.I, c3.RandomizedCredential.Cx0, c3.Proof));

			// Check over-spending 

			var sumAmountCommitment2 = Sum(c0.RandomizedCredential.Cv, c1.RandomizedCredential.Cv, c2.RandomizedCredential.Cv, c3.RandomizedCredential.Cv);
			var commitmentSumAmount2 = Sum(oreq.OverSpendingPreventionProof.SumZ * Generators.Gv, oreq.OutputValue * Generators.Gg, oreq.OverSpendingPreventionProof.SumR * Generators.Gh);

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
	}
}