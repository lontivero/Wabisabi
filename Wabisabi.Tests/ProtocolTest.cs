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
			var (r0, (r1, (r2, (r3, _)))) = GenerateRandomNumbers(4);

			var Mv0 = Commit(Scalar.Zero, r0);
			var Mv1 = Commit(Scalar.Zero, r1);
			var Mv2 = Commit(Scalar.Zero, r2);
			var Mv3 = Commit(Scalar.Zero, r3);

			var (serial0, (serial1, (serial2, (serial3, _)))) = GenerateRandomNumbers(4);
			var (s0, (s1, (s2, (s3, _)))) = GenerateRandomNumbers(4);
			var Ms0 = Commit(serial0, s0);
			var Ms1 = Commit(serial1, s1);
			var Ms2 = Commit(serial2, s2);
			var Ms3 = Commit(serial3, s3);

			// this is what we send to the coordinator
			var attr0 = new Attribute( Mv0, Ms0 );
			var attr1 =	new Attribute( Mv1, Ms1 );
			var attr2 =	new Attribute( Mv2, Ms2 );
			var attr3 =	new Attribute( Mv3, Ms3 );

			var pi_null0 = ProofOfExponent(r0, Generators.Gg);
			var pi_null1 = ProofOfExponent(r1, Generators.Gg);
			var pi_null2 = ProofOfExponent(r2, Generators.Gg);
			var pi_null3 = ProofOfExponent(r3, Generators.Gg);

			var request = new InputRegistrationRequest {
				Amount = Scalar.Zero,
				Attributes = new[]{
					attr0,
					attr1,
					attr2,
					attr3,
				},
				Pi_Null = new[]{
					pi_null0,
					pi_null1,
					pi_null2,
					pi_null3,
				},
				Pi_Sum = Sum(r0, r1, r2, r3)
			};


			// >>>>>>>>>>>>>>>>>>>> Send input to the coordinator
			//________________________________________________________________________________________
			var response = RegisterInputs(request);

			//________________________________________________________________________________________
			//
			// BOB 
			// _______________________________________________________________________________________ 
			var (cred0, (cred1, (cred2, (cred3, _)))) = response.Credentials;

			// Verify the coordinator issued the credentials using its private key
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred0.mac.U, cred0.mac.V, attr0, cred0.proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred1.mac.U, cred1.mac.V, attr1, cred1.proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred2.mac.U, cred2.mac.V, attr2, cred2.proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred3.mac.U, cred3.mac.V, attr3, cred3.proof));

			var (z0, (z1, (z2, (z3, _)))) = GenerateRandomNumbers(4);
			var rc0 = RandomizeCommitments(z0, attr0, cred0.mac);
			var rc1 = RandomizeCommitments(z1, attr1, cred1.mac);
			var rc2 = RandomizeCommitments(z2, attr2, cred2.mac);
			var rc3 = RandomizeCommitments(z3, attr3, cred3.mac);

			var pi_MAC0 = ProofOfMAC(z0, cred0.mac.t, response.iParams.I, rc0.Cx0);
			var pi_MAC1 = ProofOfMAC(z1, cred1.mac.t, response.iParams.I, rc1.Cx0);
			var pi_MAC2 = ProofOfMAC(z2, cred2.mac.t, response.iParams.I, rc2.Cx0);
			var pi_MAC3 = ProofOfMAC(z3, cred3.mac.t, response.iParams.I, rc3.Cx0);

			var pi_serial0  = ProofOfSerialNumber(z0, serial0, s0);
			var pi_serial1  = ProofOfSerialNumber(z1, serial1, s1);
			var pi_serial2  = ProofOfSerialNumber(z2, serial2, s2);
			var pi_serial3  = ProofOfSerialNumber(z3, serial3, s3);

			var outputRegistrationRequest = new OutputRegistrationRequest{
				ValidCredentialProof = new [] {
					(rc0, pi_MAC0, serial0, pi_serial0),  // how should I call these records? ValidCredentialProof?
					(rc1, pi_MAC1, serial1, pi_serial1),
					(rc2, pi_MAC2, serial2, pi_serial2),
					(rc3, pi_MAC3, serial3, pi_serial3)
				},
				OverSpendingPreventionProof = (Sum(z0, z1, z2, z3), Sum(r0, r1, r2, r3) ),
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
			var pi_params1 = ProofOfParams(sk, attr1, credential1.U, credential1.t);
			var pi_params2 = ProofOfParams(sk, attr2, credential2.U, credential2.t);
			var pi_params3 = ProofOfParams(sk, attr3, credential3.U, credential3.t);

			// This is what the coordinator responds to the client.
			return new InputRegistrationResponse {
				iParams = pk,
				Credentials = new[]{
					(credential0, pi_params0),
					(credential1, pi_params1),
					(credential2, pi_params2),
					(credential3, pi_params3)
				}
			};
		}


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
		public (MAC mac, Proof proof)[] Credentials;
	};

	class OutputRegistrationRequest
	{
		public Scalar OutputValue;
		public (Scalar Pi_Z, Scalar Pi_R) OverSpendingPreventionProof;
		public (RandomizedCommitments XCredential, Proof pi_MAC, Scalar serialNumber, Proof pi_serial)[] ValidCredentialProof;
	}
}