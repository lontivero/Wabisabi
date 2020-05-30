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

	public static class ArrayExtensions
	{
		public static T[] Shuffle<T>(this T[] list)
		{
			var rng = new Random();
			int n = list.Length;
			while (n > 1)
			{
				n--;
				int k = rng.Next(n + 1);
				(list[k], list[n]) = (list[n], list[k]);
			}
			return list;
		}
	}
}
