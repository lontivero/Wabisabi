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

		public static (GroupElement R, Scalar s) ProofOfExponent(Scalar sk, GroupElement G)
		{
			var r = RandomScalar();
			var R = r * G;
			var P = sk * G;
			var e = BuildChallenge(R, G);
			var s = r + sk * e;
			return (R, s);
		}

		public static bool VerifyProofOfExponent(GroupElement P, (GroupElement R, Scalar s) sig, GroupElement G)
		{
			var e = BuildChallenge(sig.R, G);
			return (sig.s * G) == (sig.R + e * P);
		}

		public static ProofOfMAC ProofOfKnowledgeMAC(Scalar z, Scalar t, GroupElement I, GroupElement Cx0)
		{
			var (r, a, b, c) = (RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar());
			var R = r * I; 
			var A = a * Cx0; 
			var B = b * Generators.Gx0; 
			var C = c * Generators.Gx1;

			var e = BuildChallenge(R, A, B, C, I, Cx0, Generators.Gx0, Generators.Gx1);

			var sz = r + z * e;
			var sa = a + t * e;
			var sb = b + (z * t.Negate()) * e;
			var sc = c + z * e;
			return new ProofOfMAC (R, A, B, C, sz, sa, sb, sc);
		}

		public static bool VerifyZeroKnowledgeProofMAC(GroupElement Z, GroupElement Cx1, GroupElement I, GroupElement Cx0, ProofOfMAC proof)
		{
			var gsz = proof.sz * I;
			var gsa = proof.sa * Cx0;
			var gsb = proof.sb * Generators.Gx0;
			var gsc = proof.sc * Generators.Gx1;

			var e = BuildChallenge(proof.R, proof.A, proof.B, proof.C, I, Cx0, Generators.Gx0, Generators.Gx1);

			return Sum(gsz, gsa, gsb, gsc) == Sum(proof.R, proof.A, proof.B, proof.C, (e * Cx1), (e * Z));
		}


		#endregion Proof (Schnorr signatures)

		#region Parameters

		public static ServerSecretKey GenServerSecretKey()
			=> new ServerSecretKey(RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar());

		public static (GroupElement Cw, GroupElement I) ComputeServerPublicKey(ServerSecretKey sk)
			=> ((sk.w * Generators.Gw + sk.wp * Generators.Gwp),
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

		public static Scalar Sum(Scalar[] me)
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

		#if false  //unused

		public static (GroupElement, Scalar) ProofOfExponent(Scalar z, GroupElement GG)
			=> CreateZeroKnowledgeProof(z, GG);

		public static (GroupElement R, Scalar s) CreateZeroKnowledgeProof(Scalar sk, GroupElement GG)
		{
			var r = RandomScalar();
			var R = r * GG;

			using var sha256 = SHA256Managed.Create();
			var e = new Scalar(sha256.ComputeHash(R.ToByteArray()));
 
			var s = r + sk * e;
			return (R, s);
		}

		#endif

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

	public readonly struct ProofOfSN
	{
		public ProofOfSN(GroupElement A, GroupElement B, GroupElement C, Scalar sa, Scalar sb, Scalar sc)
		{
			this.A = A;
			this.B = B;
			this.C = C;
			this.sa = sa;
			this.sb = sb;
			this.sc = sc;
		}

		public GroupElement A { get; }
		public GroupElement B { get; }
		public GroupElement C { get; }
		public Scalar sa { get; }
		public Scalar sb { get; }
		public Scalar sc { get; }
	}

	public readonly struct ProofOfMAC
	{
		public ProofOfMAC(GroupElement R, GroupElement A, GroupElement B, GroupElement C, Scalar sz, Scalar sa, Scalar sb, Scalar sc)
		{
			this.R = R;
			this.A = A;
			this.B = B;
			this.C = C;
			this.sz = sz;
			this.sa = sa;
			this.sb = sb;
			this.sc = sc;
		}
		public GroupElement R { get; }
		public GroupElement A { get; }
		public GroupElement B { get; }
		public GroupElement C { get; }
		public Scalar sz { get; }
		public Scalar sa { get; }
		public Scalar sb { get; }
		public Scalar sc { get; }
	}
}