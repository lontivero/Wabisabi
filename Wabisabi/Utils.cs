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
}
