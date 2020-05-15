﻿using System;
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

		private static GroupElement ComputePedersenCommitment(Scalar x, Scalar a, GroupElement G, GroupElement H)
			=> (x * G) + (a * H);

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
		public static (Scalar x0, Scalar x1, Scalar y0, Scalar y1) GenMACKey()
			=> (RandomScalar(), RandomScalar(), RandomScalar(), RandomScalar());

		public static (Scalar t, GroupElement U, GroupElement V) MAC((Scalar x0, Scalar x1, Scalar y0, Scalar y1) sk, GroupElement Mv, GroupElement Ms)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), (sk.y0 * Mv) + (sk.y1 * Ms), t: Crypto.RandomScalar(), U: Crypto.RandomScalar() * Generators.G);

		private static (Scalar t, GroupElement U, GroupElement V) MAC((Scalar x0, Scalar x1, Scalar y0, Scalar y1) sk, GroupElement Mv, GroupElement Ms, Scalar t, GroupElement U)
			=> ComputeAlgebraicMAC((sk.x0, sk.x1), (sk.y0 * Mv) + (sk.y1 * Ms), t, U);

		public static bool VerifyMAC((Scalar, Scalar, Scalar, Scalar) sk, GroupElement Mv, GroupElement Ms, (Scalar t, GroupElement U, GroupElement V) mac)
			=> MAC(sk, Mv, Ms, mac.t, mac.U) == mac;

		#endregion Wabisabi MAC functions


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