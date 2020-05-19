using System;
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

		public static (GroupElement, Scalar) ProofKnowledgeMAC(Scalar z, GroupElement GG)
			=> CreateZeroKnowledgeProof(z, GG);

		public static (GroupElement Cv, GroupElement Cs, GroupElement Cx0, GroupElement Cx1, GroupElement CV)  RandomizedCommitments(Scalar z, GroupElement Mv, GroupElement Ms, (Scalar t, GroupElement U, GroupElement V) credential)
			=> (Randomize(z, Generators.Gv, Mv),
				Randomize(z, Generators.Gs, Ms),
				Randomize(z, Generators.Gx0, credential.U),
				Randomize(z, Generators.Gx1, credential.t * credential.U),
				Randomize(z, Generators.GV, credential.V));

		private static GroupElement Randomize(Scalar z, GroupElement G, GroupElement H)
			=> ComputePedersenCommitment(z, Scalar.One, G, H);

		private static GroupElement ComputePedersenCommitment(Scalar a, Scalar x, GroupElement G, GroupElement H)
			=> (a * G) + (x * H);

		#endregion Pedersen Commitment Scheme functions

		#region  Algebraic MAC functions
		private static (Scalar t, GroupElement U, GroupElement V) ComputeAlgebraicMAC((Scalar x0, Scalar x1) sk, GroupElement M, Scalar t, GroupElement U)
			=> (t, U, (sk.x0 + sk.x1 * t) * U + M);

		public static (Scalar x0, Scalar x1) GenAlgebraicMACKey()
			=> (RandomScalar(), RandomScalar());

		public static (Scalar t, GroupElement U, GroupElement V) AlgebraicMAC((Scalar x0, Scalar x1) sk, GroupElement M)
			=> ComputeAlgebraicMAC(sk, M, t: Crypto.RandomScalar(), U: Crypto.RandomScalar() * Generators.G);
	
		public static bool VerifyAlgebraicMAC((Scalar, Scalar) sk, GroupElement M, (Scalar t, GroupElement U, GroupElement V) mac)
			=> AlgebraicMAC(sk, M) == mac;

		#endregion  Algebraic MAC functions


		#region Wabisabi MAC functions
		public static (Scalar w, Scalar wp, Scalar x0, Scalar x1, Scalar yv, Scalar ys) GenMACKey()
			=> (RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar());

		public static (Scalar t, GroupElement U, GroupElement V) MAC((Scalar w, Scalar wp, Scalar x0, Scalar x1, Scalar yv, Scalar ys) sk, GroupElement Mv, GroupElement Ms)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), sk.w * Generators.Gw + (sk.yv * Mv) + (sk.ys * Ms), t: Crypto.RandomScalar(), U: Crypto.RandomScalar() * Generators.G);

		private static (Scalar t, GroupElement U, GroupElement V) MAC((Scalar w, Scalar wp, Scalar x0, Scalar x1, Scalar yv, Scalar ys) sk, GroupElement Mv, GroupElement Ms, Scalar t, GroupElement U)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), (sk.yv * Mv) + (sk.ys * Ms), t, U);

		public static bool VerifyMAC((Scalar, Scalar, Scalar, Scalar, Scalar, Scalar) sk, GroupElement Mv, GroupElement Ms, (Scalar t, GroupElement U, GroupElement V) mac)
			=> MAC(sk, Mv, Ms, mac.t, mac.U) == mac;

		#endregion Wabisabi MAC functions

		#region Proof

		public static (GroupElement R, Scalar s) CreateZeroKnowledgeProof(Scalar sk, GroupElement GG)
		{
			var r = RandomScalar();
			var R = r * GG;
//			var R = r * Generators.G;

			using var sha256 = SHA256Managed.Create();
			var e = new Scalar(sha256.ComputeHash(R.ToByteArray()));
 
			var s = r + sk * e;
			return (R, s);
		}

		public static bool VerifyZeroKnowledgeProof(GroupElement P, (GroupElement R, Scalar s) sig, GroupElement GG)
		{
			using var sha256 = SHA256Managed.Create();
			var e = new Scalar(sha256.ComputeHash(sig.R.ToByteArray()));

			var gs = sig.s * GG;
//			var gs = sig.s * Generators.G;
			var xx = sig.R + e * P; 

			return gs == xx;
		}

		#endregion Proof (Schnorr signatures)

		#region Parameters
		
		public static (GroupElement Cw, GroupElement I) ComputeIParams((Scalar w, Scalar wp, Scalar x0, Scalar x1, Scalar yv, Scalar ys) sk)
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

		#endregion Utils
	}
}