using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace Wabisabi
{	
	public static class Crypto
	{
		#region Pedersen Commitment Scheme functions
		public static GroupElement Commit(Scalar value, Scalar blindingFactor)
			=> ComputePedersenCommitment(value, blindingFactor, Generators.Gg, Generators.Gh);

		public static bool OpenCommit(GroupElement commitment, Scalar a, Scalar x)
			=> Commit(a, x) == commitment;

		public static Func<Scalar, GroupElement> WithRandomFactor(Func<Scalar, Scalar, GroupElement> PedersenCommitmentFunction)
			=> (Scalar a) => PedersenCommitmentFunction(Crypto.RandomScalar(), a);

		public static (GroupElement, Scalar) Attribute(Scalar amount)
			 => Attribute(amount, Crypto.RandomScalar());

		private static (GroupElement, Scalar) Attribute(Scalar amount, Scalar r)
			=> (Commit(amount, r), r);

		public static RandomizedCommitments RandomizeCommitments(Scalar z, Scalar r, GroupElement Ma, MAC credential)
			=> new RandomizedCommitments(
				S:   r * Generators.Gs,
				Ca:  Randomize(z, Generators.Ga, Ma),
				Cx0: Randomize(z, Generators.Gx0, credential.U),
				Cx1: Randomize(z, Generators.Gx1, credential.t * credential.U),
				CV:  Randomize(z, Generators.GV, credential.V));

		public static GroupElement VerifyCredential(ServerSecretKey sk, RandomizedCommitments c)
			=> c.CV + ((sk.w * Generators.Gw) + (sk.x0 * c.Cx0) + (sk.x1 * c.Cx1) + (sk.ya * c.Ca)).Negate();

		private static GroupElement Randomize(Scalar z, GroupElement G, GroupElement M)
			=> (z * G + M);

		private static GroupElement ComputePedersenCommitment(Scalar value, Scalar blindingFactor, GroupElement G, GroupElement H)
			=> (value * G) + (blindingFactor * H);

		#endregion Pedersen Commitment Scheme functions

		#region  Algebraic MAC functions
		private static MAC ComputeAlgebraicMAC((Scalar x0, Scalar x1) sk, GroupElement M, Scalar t, GroupElement U)
			=> new MAC(t, U, (sk.x0 + sk.x1 * t) * U + M);

		public static (Scalar x0, Scalar x1) GenAlgebraicMACKey()
			=> (RandomScalar(), RandomScalar());

		public static MAC AlgebraicMAC((Scalar x0, Scalar x1) sk, GroupElement M)
			=> ComputeAlgebraicMAC(sk, M, t: Crypto.RandomScalar(), U: Crypto.RandomScalar() * Generators.G);
	
		public static bool VerifyAlgebraicMAC((Scalar, Scalar) sk, GroupElement M, MAC mac)
			=> AlgebraicMAC(sk, M) == mac;

		#endregion  Algebraic MAC functions


		#region Wabisabi MAC functions

		public static MAC ComputeMAC(ServerSecretKey sk, GroupElement Ma)
			=> ComputeMAC(sk, Ma, Crypto.RandomScalar());

		private static MAC ComputeMAC(ServerSecretKey sk, GroupElement Ma, Scalar t)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), (sk.w * Generators.Gw) + (sk.ya * Ma), t, Generators.GetNums(t));

		public static bool VerifyMAC(ServerSecretKey sk, GroupElement Ma, MAC mac)
			=> ComputeMAC(sk, Ma, mac.t) == mac;

		#endregion Wabisabi MAC functions

		#region Proof

		public static Proof ProofOfKnowledge(Scalar[] ws, GroupElement[] Gs)
		{
			var nonceKeys = new List<Scalar>();
			var nonce = new GroupElement(GE.Infinity);
			foreach (var G in Gs)
			{
				var n = RandomScalar();
				nonceKeys.Add(n);
				nonce += (n * G);
			}

			var nonces = new [] { nonce };
			var e = BuildChallenge(nonces.Concat(Gs));

			var ss = new List<Scalar>();
			foreach(var (nonceKey, witness) in Enumerable.Zip(nonceKeys, ws))
			{
				ss.Add(nonceKey + witness * e);
			}
			return new Proof (nonces, ss);
		}

		public static bool VerifyProofOfKnowledge(GroupElement[] Ps, GroupElement[] Gs, Proof proof)
		{
			var nonces = new List<GroupElement>();
			foreach (var (s, G) in Enumerable.Zip(proof.s, Gs))
			{
				nonces.Add(s * G);
			}

			var e = BuildChallenge(proof.R.Concat(Gs));

			return Sum(nonces) == Sum(proof.R) + Sum(Ps.Select(P => (e * P)));
		}

		public static Proof ProofOfExponent(Scalar sk, GroupElement G)
			=> ProofOfExponent(new[] { sk }, new[]{ G });

		public static Proof ProofOfExponent(Scalar[] sk, GroupElement G)
			=> ProofOfKnowledge(sk, Enumerable.Repeat(G, sk.Count()).ToArray());

		public static Proof ProofOfExponent(Scalar[] sk, GroupElement[] Gs)
			=> ProofOfKnowledge(sk, Gs);

		public static bool VerifyProofOfExponent(GroupElement P, GroupElement G, Proof proof)
			=> VerifyProofOfExponent(new[]{ P }, new[]{ G }, proof);

		public static bool VerifyProofOfExponent(GroupElement[] P, GroupElement G, Proof proof)
			=> VerifyProofOfKnowledge(P, Enumerable.Repeat(G, proof.s.Count()).ToArray(), proof);

		public static bool VerifyProofOfExponent(GroupElement[] P, GroupElement[] G, Proof proof)
			=> VerifyProofOfKnowledge(P, G, proof);

		public static Proof ProofOfSum(Scalar z, Scalar r)
			=> ProofOfKnowledge(new[] { z, r }, new[] { Generators.Ga, Generators.Gh });

		public static bool VerifyProofOfSum(GroupElement P, Proof proof)
			=> VerifyProofOfKnowledge(new[]{ P }, new[]{ Generators.Ga, Generators.Gh }, proof);

		public static Proof ProofOfMAC(Scalar z, Scalar t, GroupElement I, GroupElement Cx0)
			=> ProofOfKnowledge(
					new[] { z, t, (z * t.Negate()), z}, 
					new[] { I, Cx0, Generators.Gx0, Generators.Gx1});
		public static bool VerifyProofOfMAC(GroupElement Z, GroupElement Cx1, GroupElement I, GroupElement Cx0, Proof proof)
			=> VerifyProofOfKnowledge(
					new[]{ Cx1, Z},
					new[]{ I, Cx0, Generators.Gx0, Generators.Gx1}, 
					proof);

		public static Proof ProofOfSerialNumber(Scalar z, Scalar a, Scalar r)
			=> ProofOfKnowledge(
				new[] { 
					r, 
					z, r, a	},
				new[] {
					Generators.Gs, 
					Generators.Ga, Generators.Gh, Generators.Gg} );

		public static bool VerifyProofOfSerialNumber(GroupElement S, GroupElement Ca, Proof proof)
			=> VerifyProofOfKnowledge(
				new[] { S, Ca }, 
				new[] {
					Generators.Gs, 
					Generators.Ga, Generators.Gh, Generators.Gg}, 
				proof);

		public static Proof ProofOfParams(ServerSecretKey sk, GroupElement Ma, GroupElement U, Scalar t)
			=> ProofOfKnowledge(
				new[] { 
					sk.w, sk.wp, 
					Scalar.One, sk.x0, sk.x1, sk.ya,
					sk.w, sk.x0 + (sk.x1 * t), sk.ya},
				new[] { 
					Generators.Gw, Generators.Gwp, 
					Generators.GV, Generators.Gx0.Negate(), Generators.Gx1.Negate(), Generators.Ga.Negate(),
					Generators.Gw, U, Ma });

		public static bool VerifyProofOfParams(GroupElement Cw, GroupElement I, GroupElement U, GroupElement V, GroupElement Ma, Proof proof)
			=> VerifyProofOfKnowledge(
				new[] { Cw, I, V},
				new[] {
					Generators.Gw, Generators.Gwp, 
					Generators.GV, Generators.Gx0.Negate(), Generators.Gx1.Negate(), Generators.Ga.Negate(),
					Generators.Gw, U, Ma },
				proof);

		#endregion Proof (Schnorr signatures)

		#region Parameters

		public static ServerSecretKey GenServerSecretKey()
			=> new ServerSecretKey(RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar());

		public static ServerPublicKey ComputeServerPublicKey(ServerSecretKey sk)
			=> new ServerPublicKey((sk.w * Generators.Gw + sk.wp * Generators.Gwp),
				(sk.x0.Negate() * Generators.Gx0) +
				(sk.x1.Negate() * Generators.Gx1) +
				(sk.ya.Negate() * Generators.Ga ) +
				Generators.GV );

		#endregion Parameters

		#region Utils

		public static Scalar RandomScalar()
		{
			Scalar ret;
			int overflow;
			Span<byte> tmp = stackalloc byte[32];
			do
			{
				Rng.GetBytes(tmp);
				ret = new Scalar(tmp, out overflow);
			} while(overflow != 0 || ret.IsZero);
			return ret;
		}

		public static Scalar Sum(params Scalar[] me)
			=> me.Aggregate((s1, s2) => s1 + s2);

		public static GroupElement Sum(IEnumerable<GroupElement> me)
			=>Sum(me.ToArray());

		public static GroupElement Sum(params GroupElement[] me)
			=> me.Aggregate((s1, s2) => s1 + s2);

		public static Scalar BuildChallenge( IEnumerable<GroupElement> GEs)
			=> BuildChallenge(GEs.ToArray());

		public static Scalar BuildChallenge(params GroupElement[] GEs)
		{
			var byteArrays = GEs.Select(x => x.ToByteArray());
			var len = byteArrays.Sum(a => a.Length);
			var buffer = new byte[len];
			var pos = 0;
			foreach (var array in byteArrays)
			{
				Buffer.BlockCopy(array, 0, buffer, pos, array.Length);
				pos += array.Length;
			}

			using var sha256 = SHA256Managed.Create();
			return new Scalar(sha256.ComputeHash(buffer));
		}

		#endregion Utils
	}


	public readonly struct CredentialRequest
	{

		public CredentialRequest(GroupElement[] Mas, Proof rangeProof)
		{
			this.Mas = Mas;
			this.RangeProof = rangeProof;
		}

		public GroupElement[] Mas { get; }

		public Proof RangeProof { get; }
	}

	public readonly struct Credential
	{
		public Credential(MAC mac, Proof proof)
		{
			Mac = mac;
			Proof = proof;
		}

		public MAC Mac { get; }
		public Proof Proof { get;  }
	}

	public readonly struct CredentialProof
	{
		public CredentialProof(RandomizedCommitments credential, Proof pi_MAC, Proof pi_serial)
		{
			Credential = credential;
			Pi_MAC = pi_MAC;
			Pi_serial = pi_serial;	
		}

		public RandomizedCommitments Credential { get; } 
		public Proof Pi_MAC  { get; }
		public Proof Pi_serial  { get; }
	}

	public readonly struct ServerSecretKey
	{
		public ServerSecretKey(Scalar w, Scalar wp, Scalar x0, Scalar x1, Scalar ya)
		{
			this.w  = w;
			this.wp = wp;
			this.x0 = x0;
			this.x1 = x1;
			this.ya = ya;
		}

		public Scalar w { get; }
		public Scalar wp { get; }
		public Scalar x0 { get; }
		public Scalar x1 { get; }
		public Scalar ya { get; }
	}

	public readonly struct ServerPublicKey
	{
		public ServerPublicKey(GroupElement Cw, GroupElement I)
		{
			this.Cw = Cw;
			this.I = I;
		}

		public GroupElement Cw { get; }
		public GroupElement I { get; }
	}

	public readonly struct MAC
	{
		public MAC(Scalar t, GroupElement U, GroupElement V)
		{
			this.t = t;
			this.U = U;
			this.V = V;
		}

		public Scalar t { get; }
		public GroupElement U { get; }
		public GroupElement V { get; }

		public static bool operator == (MAC a, MAC b) => a.Equals(b);
		public static bool operator != (MAC a, MAC b) => !a.Equals(b);

		public bool Equals(MAC other)
		{
			return this.t == other.t && this.U == other.U && this.V == other.V;
		}

		public override bool Equals(object obj)
		{
			if (obj is MAC other)
			{
				return this.Equals(other);
			}
			return false;
		}

		public override int GetHashCode()
		{
			return HashCode.Combine(t, U, V).GetHashCode();
		}
	}

	public readonly struct RandomizedCommitments
	{
		public RandomizedCommitments(GroupElement S, GroupElement Ca, GroupElement Cx0, GroupElement Cx1, GroupElement CV)
		{
			this.S = S;
			this.Ca = Ca;
			this.Cx0 = Cx0;
			this.Cx1 = Cx1;
			this.CV = CV;
		}

		public GroupElement S { get; }
		public GroupElement Ca { get; }
		public GroupElement Cx0 { get; }
		public GroupElement Cx1 { get; }
		public GroupElement CV { get; }
	}

	public readonly struct Proof
	{
		public IEnumerable<GroupElement> R { get; }
		public IEnumerable<Scalar> s { get; }

		public Proof(IEnumerable<GroupElement> R, IEnumerable<Scalar> s)
		{
			this.R = R;
			this.s = s;
		}
	}
}