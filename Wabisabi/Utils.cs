using System;
using System.Collections.Generic;
using System.Linq;
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

		public static void Deconstruct<T>(this IList<T> list, out T first, out IList<T> rest) {

			first = list.Count > 0 ? list[0] : default(T); // or throw
			rest = list.Skip(1).ToList();
		}

		public static void Deconstruct<T>(this IList<T> list, out T first, out T second, out IList<T> rest) {
			first = list.Count > 0 ? list[0] : default(T); // or throw
			second = list.Count > 1 ? list[1] : default(T); // or throw
			rest = list.Skip(2).ToList();
		}
	}
}
