using System.Linq;
using NBitcoin.Secp256k1;
using Wabisabi;
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

			// this is what we send to the coordinator
			var a0 = Scalar.Zero;	
			var a1 = Scalar.Zero;
			var a2 = Scalar.Zero;
			var a3 = Scalar.Zero;

			var (Ma0, r0) = Attribute( a0 );
			var (Ma1, r1) = Attribute( a1 );
			var (Ma2, r2) = Attribute( a2 );
			var (Ma3, r3) = Attribute( a3 );

			var request = new RegistrationRequest {
				CredentialRequests = new CredentialRequest(
					new[]{ Ma0, Ma1, Ma2, Ma3 },
					ProofOfExponent(new[]{ r0, r1, r2, r3 }, Generators.Gh)
				),
				Credentials = new CredentialProof[0],
				BalanceProof = ProofOfExponent(Scalar.Zero, Generators.Gg),
				DeltaValue = Scalar.Zero,
			};


			// >>>>>>>>>>>>>>>>>>>> Send input to the coordinator
			//________________________________________________________________________________________
			var response = RegisterInputs(request);

			var (cred0, (cred1, (cred2, (cred3, _)))) = response.Credentials;

			// Verify the coordinator issued the credentials using its private key
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred0.Mac.U, cred0.Mac.V, Ma0, cred0.Proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred1.Mac.U, cred1.Mac.V, Ma1, cred1.Proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred2.Mac.U, cred2.Mac.V, Ma2, cred2.Proof));
			Assert.True(VerifyProofOfParams(pk.Cw, pk.I, cred3.Mac.U, cred3.Mac.V, Ma3, cred3.Proof));

			var (z0, (z1, (z2, (z3, _)))) = GenerateRandomNumbers(4);
			var rc0 = RandomizeCommitments(z0, r0, Ma0, cred0.Mac);
			var rc1 = RandomizeCommitments(z1, r1, Ma1, cred1.Mac);
			var rc2 = RandomizeCommitments(z2, r2, Ma2, cred2.Mac);
			var rc3 = RandomizeCommitments(z3, r3, Ma3, cred3.Mac);

			var pi_MAC0 = ProofOfMAC(z0, cred0.Mac.t, response.iParams.I, rc0.Cx0);
			var pi_MAC1 = ProofOfMAC(z1, cred1.Mac.t, response.iParams.I, rc1.Cx0);
			var pi_MAC2 = ProofOfMAC(z2, cred2.Mac.t, response.iParams.I, rc2.Cx0);
			var pi_MAC3 = ProofOfMAC(z3, cred3.Mac.t, response.iParams.I, rc3.Cx0);

			var pi_serial0  = ProofOfSerialNumber(z0, a0, r0);
			var pi_serial1  = ProofOfSerialNumber(z1, a1, r1);
			var pi_serial2  = ProofOfSerialNumber(z2, a2, r2);
			var pi_serial3  = ProofOfSerialNumber(z3, a3, r3);

			var (rp0, rp1, rp2, rp3) = (r0, r1, r2, r3);

			a0 = new Scalar(100_000);
			a1 = new Scalar(200_000);
			a2 = new Scalar( 50_000);
			a3 = new Scalar(  1_234);

			(Ma0, r0) = Attribute(a0);
			(Ma1, r1) = Attribute(a1);
			(Ma2, r2) = Attribute(a2);
			(Ma3, r3) = Attribute(a3);

			var z = Sum(z0, z1, z2, z3);
			var delta_r = Sum(rp0, rp1, rp2, rp3) + Sum(r0, r1, r2, r3).Negate();
			var pi_sum = ProofOfSum(z, delta_r);

			request = new RegistrationRequest {
				CredentialRequests = new CredentialRequest(
					new[]{ Ma0, Ma1, Ma2, Ma3 },
					request.CredentialRequests.RangeProof
				),
				Credentials = new [] {
					new CredentialProof(rc0, pi_MAC0, pi_serial0),  // how should I call these records? ValidCredentialProof?
					new CredentialProof(rc1, pi_MAC1, pi_serial1),
					new CredentialProof(rc2, pi_MAC2, pi_serial2),
					new CredentialProof(rc3, pi_MAC3, pi_serial3)
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
				CredentialRequests = new CredentialRequest(new GroupElement[0], new Proof()),
				Credentials = new [] {
					new CredentialProof(rc0, pi_MAC0, pi_serial0),  // how should I call these records? ValidCredentialProof?
					new CredentialProof(rc1, pi_MAC1, pi_serial1),
					new CredentialProof(rc2, pi_MAC2, pi_serial2),
					new CredentialProof(rc3, pi_MAC3, pi_serial3)
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

			var Mas = request.CredentialRequests.Mas;

			// Checks the proofs (amounts and range)
			if (request.DeltaValue == Scalar.Zero)
			{
				// Proof of NULL
				Assert.True(VerifyProofOfExponent(Mas, Generators.Gh, request.CredentialRequests.RangeProof));
			}
			else
			{
				if (request.Credentials.Length > 0)
				{
					var (c0, (c1, (c2, (c3, _)))) = request.Credentials;

					var B = (request.DeltaValue * Generators.Gg) +
							(c0.Credential.Ca + c1.Credential.Ca + c2.Credential.Ca + c3.Credential.Ca) +
							Sum(Mas).Negate();
					Assert.True(VerifyProofOfSum(B, request.BalanceProof));
				}
			}

			// We must generate the proof of knowledge of the secret key here
			var (cr0, (cr1, (cr2, (cr3, _)))) = Mas;
			var credential0 = ComputeMAC(sk, cr0);
			var credential1 = ComputeMAC(sk, cr1);
			var credential2 = ComputeMAC(sk, cr2);
			var credential3 = ComputeMAC(sk, cr3);

			var pi_params0 = ProofOfParams(sk, cr0, credential0.U, credential0.t);
			var pi_params1 = ProofOfParams(sk, cr1, credential1.U, credential1.t);
			var pi_params2 = ProofOfParams(sk, cr2, credential2.U, credential2.t);
			var pi_params3 = ProofOfParams(sk, cr3, credential3.U, credential3.t);

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

			Assert.True(VerifyProofOfSerialNumber(c0.Credential.S, c0.Credential.Ca, c0.Pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c1.Credential.S, c1.Credential.Ca, c1.Pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c2.Credential.S, c2.Credential.Ca, c2.Pi_serial));
			Assert.True(VerifyProofOfSerialNumber(c3.Credential.S, c3.Credential.Ca, c3.Pi_serial));
			
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
		public CredentialRequest CredentialRequests;
		public CredentialProof[] Credentials;
		public Proof BalanceProof;
	}

	class RegistrationResponse
	{
		public ServerPublicKey iParams;
		public Credential[] Credentials;
	};
}