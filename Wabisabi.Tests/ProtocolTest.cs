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

			var pi_null0 = ProofOfExponent(r0, Generators.Gg);  // this is for the special case. It should use bulletproof
			var pi_null1 = ProofOfExponent(r1, Generators.Gg);
			var pi_null2 = ProofOfExponent(r2, Generators.Gg);
			var pi_null3 = ProofOfExponent(r3, Generators.Gg);

			var request = new RegistrationRequest {
				CredentialRequests = new[]{
					new CredentialRequest(attr0, pi_null0), 
					new CredentialRequest(attr1, pi_null1), 
					new CredentialRequest(attr2, pi_null2), 
					new CredentialRequest(attr3, pi_null3) 
				},
				Credentials = new CredentialProof[0],
				BalanceProof = pi_null0,
				DeltaValue = Scalar.Zero,
			};


			// >>>>>>>>>>>>>>>>>>>> Send input to the coordinator
			//________________________________________________________________________________________
			var response = RegisterInputs(request);

			// Test reissuance
			var (cred0, (cred1, (cred2, (cred3, _)))) = response.Credentials;

			// Verify the coordinator issued the credentials using its private key
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred0.Mac.U, cred0.Mac.V, attr0, cred0.Proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred1.Mac.U, cred1.Mac.V, attr1, cred1.Proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred2.Mac.U, cred2.Mac.V, attr2, cred2.Proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred3.Mac.U, cred3.Mac.V, attr3, cred3.Proof));

			var (z0, (z1, (z2, (z3, _)))) = GenerateRandomNumbers(4);
			var rc0 = RandomizeCommitments(z0, attr0, cred0.Mac);
			var rc1 = RandomizeCommitments(z1, attr1, cred1.Mac);
			var rc2 = RandomizeCommitments(z2, attr2, cred2.Mac);
			var rc3 = RandomizeCommitments(z3, attr3, cred3.Mac);

			var pi_MAC0 = ProofOfMAC(z0, cred0.Mac.t, response.iParams.I, rc0.Cx0);
			var pi_MAC1 = ProofOfMAC(z1, cred1.Mac.t, response.iParams.I, rc1.Cx0);
			var pi_MAC2 = ProofOfMAC(z2, cred2.Mac.t, response.iParams.I, rc2.Cx0);
			var pi_MAC3 = ProofOfMAC(z3, cred3.Mac.t, response.iParams.I, rc3.Cx0);

			var pi_serial0  = ProofOfSerialNumber(z0, serial0, s0);
			var pi_serial1  = ProofOfSerialNumber(z1, serial1, s1);
			var pi_serial2  = ProofOfSerialNumber(z2, serial2, s2);
			var pi_serial3  = ProofOfSerialNumber(z3, serial3, s3);

			var (rp0, rp1, rp2, rp3) = (r0, r1, r2, r3);
			(r0, (r1, (r2, (r3, _)))) = GenerateRandomNumbers(4);

			Mv0 = Commit(new Scalar(100_000), r0);
			Mv1 = Commit(new Scalar(200_000), r1);
			Mv2 = Commit(new Scalar( 50_000), r2);
			Mv3 = Commit(new Scalar(  1_234), r3);

			(serial0, (serial1, (serial2, (serial3, _)))) = GenerateRandomNumbers(4);
			(s0, (s1, (s2, (s3, _)))) = GenerateRandomNumbers(4);
			Ms0 = Commit(serial0, s0);
			Ms1 = Commit(serial1, s1);
			Ms2 = Commit(serial2, s2);
			Ms3 = Commit(serial3, s3);

			// this is what we send to the coordinator
			attr0 = new Attribute( Mv0, Ms0 );
			attr1 =	new Attribute( Mv1, Ms1 );
			attr2 =	new Attribute( Mv2, Ms2 );
			attr3 =	new Attribute( Mv3, Ms3 );

			var z = Sum(z0, z1, z2, z3);
			var r = Sum(rp0, rp1, rp2, rp3) + Sum(r0, r1, r2, r3).Negate();
			var pi_sum = ProofOfSum(z, r);

			request = new RegistrationRequest {
				CredentialRequests = new[]{
					new CredentialRequest(attr0, pi_null0), 
					new CredentialRequest(attr1, pi_null1), 
					new CredentialRequest(attr2, pi_null2), 
					new CredentialRequest(attr3, pi_null3) 
				},
				Credentials = new [] {
					new CredentialProof(rc0, pi_MAC0, serial0, pi_serial0),  // how should I call these records? ValidCredentialProof?
					new CredentialProof(rc1, pi_MAC1, serial1, pi_serial1),
					new CredentialProof(rc2, pi_MAC2, serial2, pi_serial2),
					new CredentialProof(rc3, pi_MAC3, serial3, pi_serial3)
				},
				BalanceProof = pi_sum,
				DeltaValue = new Scalar(351_234),
			};

			// >>>>>>>>>>>>>>>>>>>> Send input to the coordinator
			//________________________________________________________________________________________
			response = RegisterInputs(request);

			//________________________________________________________________________________________
			//
			// BOB 
			// _______________________________________________________________________________________ 

			var outputRegistrationRequest = new RegistrationRequest{
				CredentialRequests = new CredentialRequest[0],
				Credentials = new [] {
					new CredentialProof(rc0, pi_MAC0, serial0, pi_serial0),  // how should I call these records? ValidCredentialProof?
					new CredentialProof(rc1, pi_MAC1, serial1, pi_serial1),
					new CredentialProof(rc2, pi_MAC2, serial2, pi_serial2),
					new CredentialProof(rc3, pi_MAC3, serial3, pi_serial3)
				},
				BalanceProof = pi_sum,
				DeltaValue = new Scalar(100_000)
			};

			RegisterOutputs(outputRegistrationRequest);
		}

		//________________________________________________________________________________________
		//
		// COORDINATOR
		// _______________________________________________________________________________________ 
		private ServerSecretKey sk = GenServerSecretKey();  			// ServerSecretParams
		private ServerPublicKey pk;


		private RegistrationResponse RegisterInputs(RegistrationRequest request)
		{
			pk = ComputeServerPublicKey(sk);

			var (cr0, (cr1, (cr2, (cr3, _)))) = request.CredentialRequests;

			// Checks the proofs (amounts and range)
			if (request.DeltaValue == Scalar.Zero)
			{
				// Proof of NULL
				Assert.True(VerifyProofOfExponent(cr0.Attribute.Mv, Generators.Gg, cr0.RangeProof));
				Assert.True(VerifyProofOfExponent(cr1.Attribute.Mv, Generators.Gg, cr1.RangeProof));
				Assert.True(VerifyProofOfExponent(cr2.Attribute.Mv, Generators.Gg, cr2.RangeProof));
				Assert.True(VerifyProofOfExponent(cr3.Attribute.Mv, Generators.Gg, cr3.RangeProof));
			}
			else
			{
				if (request.Credentials.Length > 0)
				{
					var (c0, (c1, (c2, (c3, _)))) = request.Credentials;

					var B = (request.DeltaValue * Generators.Gh) +
							(c0.Credential.Cv + c1.Credential.Cv + c2.Credential.Cv + c3.Credential.Cv) +
							(cr0.Attribute.Mv + cr1.Attribute.Mv + cr2.Attribute.Mv + cr3.Attribute.Mv).Negate(); 
					Assert.True(VerifyProofOfSum(B, request.BalanceProof));
				}
			}

			// We must generate the proof of knowledge of the secret key here
			var credential0 = ComputeMAC(sk, cr0.Attribute);
			var credential1 = ComputeMAC(sk, cr1.Attribute);
			var credential2 = ComputeMAC(sk, cr2.Attribute);
			var credential3 = ComputeMAC(sk, cr3.Attribute);

			var pi_params0 = ProofOfParams(sk, cr0.Attribute, credential0.U, credential0.t);
			var pi_params1 = ProofOfParams(sk, cr1.Attribute, credential1.U, credential1.t);
			var pi_params2 = ProofOfParams(sk, cr2.Attribute, credential2.U, credential2.t);
			var pi_params3 = ProofOfParams(sk, cr3.Attribute, credential3.U, credential3.t);

			// This is what the coordinator responds to the client.
			return new RegistrationResponse {
				iParams = pk,
				Credentials = new[]{
					new Credential(credential0, pi_params0),
					new Credential(credential1, pi_params1),
					new Credential(credential2, pi_params2),
					new Credential(credential3, pi_params3)
				}
			};
		}


		void RegisterOutputs(RegistrationRequest request)
		{
			//var (cr0, (cr1, (cr2, (cr3, _)))) = request.CredentialRequests;
			var (c0, (c1, (c2, (c3, _)))) = request.Credentials;

			// Check Bob has valid credentials
			var Z0 = VerifyCredential(sk, c0.Credential);
			var Z1 = VerifyCredential(sk, c1.Credential);
			var Z2 = VerifyCredential(sk, c2.Credential);
			var Z3 = VerifyCredential(sk, c3.Credential);

			Assert.True(VerifyProofOfSerialNumber(c0.Credential.Cs, c0.Pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c1.Credential.Cs, c1.Pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c2.Credential.Cs, c2.Pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c3.Credential.Cs, c3.Pi_serial));
			
			// Check serial numbers are not reused
			// c0.serialNumber is not in serailNumberHashSet and so on.

			var I = pk.I;
			Assert.True(VerifyProofOfMAC(Z0, c0.Credential.Cx1, I, c0.Credential.Cx0, c0.Pi_MAC));
			Assert.True(VerifyProofOfMAC(Z1, c1.Credential.Cx1, I, c1.Credential.Cx0, c1.Pi_MAC));
			Assert.True(VerifyProofOfMAC(Z2, c2.Credential.Cx1, I, c2.Credential.Cx0, c2.Pi_MAC));
			Assert.True(VerifyProofOfMAC(Z3, c3.Credential.Cx1, I, c3.Credential.Cx0, c3.Pi_MAC));

	}

		private static Scalar[] GenerateRandomNumbers(int n)
			=> Enumerable.Range(0, n).Select(_=> RandomScalar()).ToArray();
	}


	//________________________________________________________________________________________
	//
	// Protocol MESSAGES
	// _______________________________________________________________________________________ 
	public class RegistrationRequest
	{
		public Scalar DeltaValue;
		public CredentialRequest[] CredentialRequests;
		public CredentialProof[] Credentials;
		public Proof BalanceProof;
	}

	class RegistrationResponse
	{
		public ServerPublicKey iParams;
		public Credential[] Credentials;
	};
}