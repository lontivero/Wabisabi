using System;
using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public static class Rng
	{
		private static RandomNumberGenerator RandomNumberGenerator = RandomNumberGenerator.Create();

		public static void GetBytes(Span<byte> buffer)
		{
			RandomNumberGenerator.GetBytes(buffer);
		}
	}

	public class Crypto
	{
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

		public static Scalar RandomScalarForValue()
		{
			var ret = RandomScalar();
			ret.ShrInt(26, out ret);
			return ret;
		}
	}
}
