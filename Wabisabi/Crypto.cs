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
		public static GroupElement Commit(Scalar a, Scalar x)
			=> ComputePedersenCommitment(a, x, Generators.Gg, Generators.Gh);

		public static bool OpenCommit(GroupElement commitment, Scalar a, Scalar x)
			=> Commit(a, x) == commitment;

		public static Func<Scalar, GroupElement> WithRandomFactor(Func<Scalar, Scalar, GroupElement> PedersenCommitmentFunction)
			=> (Scalar a) => PedersenCommitmentFunction(Crypto.RandomScalar(), a);

		public static RandomizedCommitments RandomizeCommitments(Scalar z, Attribute attr, MAC credential)
			=> new RandomizedCommitments(
				Randomize(z, Generators.Gv, attr.Mv),
				Randomize(z, Generators.Gs, attr.Ms),
				Randomize(z, Generators.Gx0, credential.U),
				Randomize(z, Generators.Gx1, credential.t * credential.U),
				Randomize(z, Generators.GV, credential.V));

		public static GroupElement VerifyCredential(ServerSecretKey sk, RandomizedCommitments c)
			=> c.CV + ((sk.w * Generators.Gw) + (sk.x0 * c.Cx0) + (sk.x1 * c.Cx1) + (sk.yv * c.Cv)  + (sk.ys * c.Cs)).Negate();

		private static GroupElement Randomize(Scalar z, GroupElement G, GroupElement H)
			=> ComputePedersenCommitment(Scalar.One, z, G, H);

		private static GroupElement ComputePedersenCommitment(Scalar a, Scalar x, GroupElement G, GroupElement H)
			=> (x * G) + (a * H);

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

		public static MAC ComputeMAC(ServerSecretKey sk, Attribute attr)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), sk.w * Generators.Gw + (sk.yv * attr.Mv) + (sk.ys * attr.Ms), t: Crypto.RandomScalar(), U: Crypto.RandomScalar() * Generators.G);

		private static MAC ComputeMAC(ServerSecretKey sk, Attribute attr, Scalar t, GroupElement U)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), (sk.yv * attr.Mv) + (sk.ys * attr.Ms), t, U);

		public static bool VerifyMAC(ServerSecretKey sk, Attribute attr, MAC mac)
			=> ComputeMAC(sk, attr, mac.t, mac.U) == mac;

		#endregion Wabisabi MAC functions

		#region Proof

		public static Proof ProofOfKnowledge(Scalar[] ws, GroupElement[] Gs)
		{
			var nonceKeys = new List<Scalar>();
			var nonces = new List<GroupElement>();
			foreach (var G in Gs)
			{
				var n = RandomScalar();
				nonceKeys.Add(n);
				nonces.Add(n * G);
			}

			var e = BuildChallenge(nonces.Concat(Gs));

			var ss = new List<Scalar>();
			foreach(var (nonceKey, witness) in Enumerable.Zip(nonceKeys, ws))
			{
				ss.Add(nonceKey + witness * e);
			}
			return new Proof (Enumerable.Zip(nonces, ss));
		}

		public static bool VerifyProofOfKnowledge(GroupElement[] Ps, GroupElement[] Gs, Proof proof)
		{
			var nonces = new List<GroupElement>();
			foreach (var (pi, G) in Enumerable.Zip(proof.Proofs, Gs))
			{
				nonces.Add(pi.s * G);
			}

			var Rs = proof.Proofs.Select(p => p.R);
			var e = BuildChallenge(Rs.Concat(Gs));

			return Sum(nonces) == Sum(Rs) + Sum(Ps.Select(P => (e * P)));
		}

		public static Proof ProofOfExponent(Scalar sk, GroupElement G)
			=> ProofOfKnowledge(new[] { sk }, new[] { G });

		public static bool VerifyProofOfExponent(GroupElement P, GroupElement G, Proof proof)
			=> VerifyProofOfKnowledge(new[]{ P }, new[]{ G }, proof);

		public static Proof ProofOfMAC(Scalar z, Scalar t, GroupElement I, GroupElement Cx0)
			=> ProofOfKnowledge(
					new[] { z, t, (z * t.Negate()), z}, 
					new[] { I, Cx0, Generators.Gx0, Generators.Gx1});
		public static bool VerifyProofOfMAC(GroupElement Z, GroupElement Cx1, GroupElement I, GroupElement Cx0, Proof proof)
			=> VerifyProofOfKnowledge(
					new[]{ Cx1, Z},
					new[]{ I, Cx0, Generators.Gx0, Generators.Gx1}, 
					proof);

		public static Proof ProofOfSerialNumber(Scalar z, Scalar r, Scalar s)
			=> ProofOfKnowledge(
				new[] { z, r, s},
				new[] {Generators.Gs, Generators.Gh, Generators.Gg} );

		public static bool VerifyProofOfSerialNumber(GroupElement Cs, Proof proof)
			=> VerifyProofOfKnowledge(
				new[] { Cs }, 
				new[] {Generators.Gs, Generators.Gh, Generators.Gg}, 
				proof);

		public static Proof ProofOfParams(ServerSecretKey sk, Attribute att, GroupElement U, Scalar t)
			=> ProofOfKnowledge(
				new[] { 
					sk.w, sk.wp, 
					Scalar.One, sk.x0, sk.x1, sk.yv, sk.ys,
					sk.w, sk.x0 + (sk.x1 * t), sk.yv, sk.ys},
				new[] { 
					Generators.Gw, Generators.Gwp, 
					Generators.GV, Generators.Gx0.Negate(), Generators.Gx1.Negate(), Generators.Gv.Negate(), Generators.Gs.Negate(),
					Generators.Gw, U, att.Mv, att.Ms });

		public static bool VerifyProofOfParams(GroupElement Cw, GroupElement I, GroupElement U, GroupElement V, Attribute att, Proof proof)
			=> VerifyProofOfKnowledge(
				new[] { Cw, I, V},
				new[] {
					Generators.Gw, Generators.Gwp, 
					Generators.GV, Generators.Gx0.Negate(), Generators.Gx1.Negate(), Generators.Gv.Negate(), Generators.Gs.Negate(),
					Generators.Gw, U, att.Mv, att.Ms },
				proof);

		#endregion Proof (Schnorr signatures)

		#region Parameters

		public static ServerSecretKey GenServerSecretKey()
			=> new ServerSecretKey(RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar());

		public static ServerPublicKey ComputeServerPublicKey(ServerSecretKey sk)
			=> new ServerPublicKey((sk.w * Generators.Gw + sk.wp * Generators.Gwp),
				(sk.x0.Negate() * Generators.Gx0) + 
				(sk.x1.Negate() * Generators.Gx1) + 
				(sk.yv.Negate() * Generators.Gv ) + 
				(sk.ys.Negate() * Generators.Gs ) +
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

	public readonly struct Attribute 
	{
		public Attribute(GroupElement mv, GroupElement ms)
		{
			this.Mv = mv; 
			this.Ms = ms; 
		}

		public GroupElement Mv { get; } 
		public GroupElement Ms { get; }
	}

	public readonly struct ServerSecretKey
	{
		public ServerSecretKey(Scalar w, Scalar wp, Scalar x0, Scalar x1, Scalar yv, Scalar ys)
		{
			this.w  = w;
			this.wp = wp;
			this.x0 = x0;
			this.x1 = x1;
			this.yv = yv;
			this.ys = ys;
		}

		public Scalar w { get; }
		public Scalar wp { get; }
		public Scalar x0 { get; }
		public Scalar x1 { get; }
		public Scalar yv { get; }
		public Scalar ys { get; }
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
		public RandomizedCommitments(GroupElement Cv, GroupElement Cs, GroupElement Cx0, GroupElement Cx1, GroupElement CV)
		{
			this.Cv = Cv;
			this.Cs = Cs;
			this.Cx0 = Cx0;
			this.Cx1 = Cx1;
			this.CV = CV;
		}

		public GroupElement Cv { get; }
		public GroupElement Cs { get; }
		public GroupElement Cx0 { get; }
		public GroupElement Cx1 { get; }
		public GroupElement CV { get; }
	}

	public readonly struct Proof
	{
		public readonly IEnumerable<(GroupElement R, Scalar s)> Proofs { get; }

		public Proof(IEnumerable<(GroupElement R, Scalar s)> proofs)
		{
			this.Proofs = proofs;
		}
	}
}