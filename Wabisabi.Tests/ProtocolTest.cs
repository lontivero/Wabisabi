using System.Linq;
using NBitcoin.Secp256k1;
using Xunit;
using static Wabisabi.Crypto;

namespace Wabisabi.Tests
{
	public class ProtocolTests
	{
		[Fact]
		public void Protocol()
		{
			//_______________________________________________________________________________________
			//
			// ALICE 
			// _______________________________________________________________________________________ 
			var r = GenerateRandomNumbers(4);
			var s = GenerateRandomNumbers(4);

			var Mv0 = Commit(Scalar.Zero, r[0]);
			var Mv1 = Commit(Scalar.Zero, r[1]);
			var Mv2 = Commit(Scalar.Zero, r[2]);
			var Mv3 = Commit(Scalar.Zero, r[3]);

			var pi_null0 = ProofOfExponent(r[0], Generators.Gg);
			var pi_null1 = ProofOfExponent(r[1], Generators.Gg);
			var pi_null2 = ProofOfExponent(r[2], Generators.Gg);
			var pi_null3 = ProofOfExponent(r[3], Generators.Gg);

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
			var pi_null = new[]{
				pi_null0,
				pi_null1,
				pi_null2,
				pi_null3,
			};

			var request = new InputRegistrationRequest {
				Amount = Scalar.Zero,
				Attributes = attributes,
				Pi_Null = pi_null,
				Pi_Sum = Sum(r)
			};

			var response = RegisterInputs(request);

			//_______________________________________________________________________________________
			//
			// BOB 
			// _______________________________________________________________________________________ 
			var z = GenerateRandomNumbers(4);
			var rc0 = RandomizeCommitments(z[0], attributes[0], response.Credentials[0]);
			var rc1 = RandomizeCommitments(z[1], attributes[1], response.Credentials[1]);
			var rc2 = RandomizeCommitments(z[2], attributes[2], response.Credentials[2]);
			var rc3 = RandomizeCommitments(z[3], attributes[3], response.Credentials[3]);

			var pi_MAC0 = ProofOfMAC(z[0], response.Credentials[0].t, response.iParams.I, rc0.Cx0);
			var pi_MAC1 = ProofOfMAC(z[1], response.Credentials[1].t, response.iParams.I, rc1.Cx0);
			var pi_MAC2 = ProofOfMAC(z[2], response.Credentials[2].t, response.iParams.I, rc2.Cx0);
			var pi_MAC3 = ProofOfMAC(z[3], response.Credentials[3].t, response.iParams.I, rc3.Cx0);

			var pi_serial0  = ProofOfSerialNumber(z[0], serialNumbers[0], s[0]);
			var pi_serial1  = ProofOfSerialNumber(z[1], serialNumbers[1], s[1]);
			var pi_serial2  = ProofOfSerialNumber(z[2], serialNumbers[2], s[2]);
			var pi_serial3  = ProofOfSerialNumber(z[3], serialNumbers[3], s[3]);

			var outputRegistrationRequest = new OutputRegistrationRequest{
				ValidCredentialProof = new [] {
					(rc0, pi_MAC0, serialNumbers[0], pi_serial0),  // how should I call these records? ValidCredentialProof?
					(rc1, pi_MAC1, serialNumbers[1], pi_serial1),
					(rc2, pi_MAC2, serialNumbers[2], pi_serial2),
					(rc3, pi_MAC3, serialNumbers[3], pi_serial3)
				},
				OverSpendingPreventionProof = (Sum(z), Sum(r) ),
				OutputValue = new Scalar(0)
			};

			RegisterOutputs(outputRegistrationRequest);
		}

		//_______________________________________________________________________________________
		//
		// COORDINATOR
		// _______________________________________________________________________________________ 
		private ServerSecretKey sk = GenServerSecretKey();  			// ServerSecretParams
		private ServerPublicKey pk;


		private InputRegistrationResponse RegisterInputs(InputRegistrationRequest request)
		{
			pk = ComputeServerPublicKey(sk);

			var (attr0, (attr1, (attr2, (attr3, _)))) = request.Attributes as Attribute[];
			var (pi_null0, (pi_null1, (pi_null2, (pi_null3, _)))) = request.Pi_Null as Proof[];

			// Checks the proofs (amounts and range)
			Assert.True(VerifyProofOfExponent(attr0.Mv, Generators.Gg, pi_null0));
			Assert.True(VerifyProofOfExponent(attr1.Mv, Generators.Gg, pi_null1));
			Assert.True(VerifyProofOfExponent(attr2.Mv, Generators.Gg, pi_null2));
			Assert.True(VerifyProofOfExponent(attr3.Mv, Generators.Gg, pi_null3));

			var sumAmountCommitment = Sum(attr0.Mv, attr1.Mv, attr2.Mv, attr3.Mv);
			var CommitmentSumAmount = Commit(request.Amount, request.Pi_Sum);
			Assert.Equal(sumAmountCommitment, CommitmentSumAmount);
			// Checks the amount ranges..... coming soon

			// We must generate the proof of knowledge of the secret key here
			var credential0 = ComputeMAC(sk, attr0);
			var credential1 = ComputeMAC(sk, attr1);
			var credential2 = ComputeMAC(sk, attr2);
			var credential3 = ComputeMAC(sk, attr3);

			var pi_params0 = ProofOfParams(sk, attr0, credential0.U, credential0.t);
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, credential0.V, attr0, credential0.U, pi_params0));

			// This is what the coordinator responds to the client.
			return new InputRegistrationResponse {
				iParams = pk,
				Credentials = new[]{
					credential0,
					credential1,
					credential2,
					credential3
				}
			};
		}

		private static Proof ProofOfParams(ServerSecretKey sk, Attribute att, GroupElement U, Scalar t)
			=> ProofOfKnowledge(
				new[] { 
					sk.w, sk.wp, 
					Scalar.One, sk.x0, sk.x1, sk.yv, sk.ys,
					sk.w, sk.x0 + (sk.x1 * t), sk.yv, sk.ys},
				new[] { 
					Generators.Gw, Generators.Gwp, 
					Generators.GV, Generators.Gx0.Negate(), Generators.Gx1.Negate(), Generators.Gv.Negate(), Generators.Gs.Negate(),
					Generators.Gw, U, att.Mv, att.Ms });

		public static bool VerifyProofOfParams(GroupElement Cw, GroupElement I, GroupElement V, Attribute att, GroupElement U, Proof proof)
			=> VerifyProofOfKnowledge(
				new[] { Cw, I, V},
				new[] {
					Generators.Gw, Generators.Gwp, 
					Generators.GV, Generators.Gx0.Negate(), Generators.Gx1.Negate(), Generators.Gv.Negate(), Generators.Gs.Negate(),
					Generators.Gw, U, att.Mv, att.Ms },
				proof);

		void RegisterOutputs(OutputRegistrationRequest outputRegistrationRequest)
		{
			var (c0, (c1, (c2, (c3, _)))) = outputRegistrationRequest.ValidCredentialProof;
			// Check Bob has valid credentials
			var Z0 = VerifyCredential(sk, c0.XCredential);
			var Z1 = VerifyCredential(sk, c1.XCredential);
			var Z2 = VerifyCredential(sk, c2.XCredential);
			var Z3 = VerifyCredential(sk, c3.XCredential);

			Assert.True(VerifyProofOfSerialNumber(c0.XCredential.Cs, c0.pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c1.XCredential.Cs, c1.pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c2.XCredential.Cs, c2.pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c3.XCredential.Cs, c3.pi_serial));

			var I = pk.I;
			Assert.True(VerifyProofOfMAC(Z0, c0.XCredential.Cx1, I, c0.XCredential.Cx0, c0.pi_MAC));
			Assert.True(VerifyProofOfMAC(Z1, c1.XCredential.Cx1, I, c1.XCredential.Cx0, c1.pi_MAC));
			Assert.True(VerifyProofOfMAC(Z2, c2.XCredential.Cx1, I, c2.XCredential.Cx0, c2.pi_MAC));
			Assert.True(VerifyProofOfMAC(Z3, c3.XCredential.Cx1, I, c3.XCredential.Cx0, c3.pi_MAC));

			// Check over-spending 
			var sumAmountCommitment2 = Sum(c0.XCredential.Cv, c1.XCredential.Cv, c2.XCredential.Cv, c3.XCredential.Cv);
			var commitmentSumAmount2 = Sum(outputRegistrationRequest.OverSpendingPreventionProof.Pi_Z * Generators.Gv, outputRegistrationRequest.OutputValue * Generators.Gh, outputRegistrationRequest.OverSpendingPreventionProof.Pi_R * Generators.Gg);

			Assert.Equal(sumAmountCommitment2, commitmentSumAmount2);
		}

		private static Scalar[] GenerateRandomNumbers(int n)
			=> Enumerable.Range(0, n).Select(_=> RandomScalar()).ToArray();
	}


	public class InputRegistrationRequest
	{
		public Scalar Amount;
		public Attribute[] Attributes;
		public Proof[] Pi_Null;
		public Scalar Pi_Sum;
	}

	class InputRegistrationResponse
	{
		public ServerPublicKey iParams;
		public MAC[] Credentials;
	};

	class OutputRegistrationRequest
	{
		public Scalar OutputValue;
		public (Scalar Pi_Z, Scalar Pi_R) OverSpendingPreventionProof;
		public (RandomizedCommitments XCredential, Proof pi_MAC, Scalar serialNumber, Proof pi_serial)[] ValidCredentialProof;
	}
}