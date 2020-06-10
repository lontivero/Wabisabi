using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public class Generators
	{
		public static readonly GroupElement G = new GroupElement(EC.G);

		// Generators for MAC and Show
		public static readonly GroupElement Gw = GroupElementFromText(nameof(Gw));
		public static readonly GroupElement Gwp = GroupElementFromText(nameof(Gwp));
		public static readonly GroupElement Gx0 = GroupElementFromText(nameof(Gx0));
		public static readonly GroupElement Gx1 = GroupElementFromText(nameof(Gx1));
		public static readonly GroupElement GV = GroupElementFromText(nameof(GV));

		// Generators for Pedersen commitments
		public static readonly GroupElement Gg = GroupElementFromText(nameof(Gg));
		public static readonly GroupElement Gh = GroupElementFromText(nameof(Gh));

		// Generator for attributes M_{ai}
		public static readonly GroupElement Ga = GroupElementFromText(nameof(Ga));

		// Generator for serial numbers 
		public static readonly GroupElement Gs = GroupElementFromText(nameof(Gs));


		public static GroupElement GetNums(Scalar i)
		{
			if( !NumsCache.TryGetValue(i, out var ge))
			{
				ge = GroupElementFromBytes(i.ToBytes());
				NumsCache.Add(i, ge);
			}
			return ge;
		}

		private static GroupElement GroupElementFromBytes(byte[] bytes)
		{
			return GroupElementFromText(Encoding.UTF8.GetString(bytes));
		}

		private static GroupElement GroupElementFromText(string text)
		{
			FE x;
			GE ge;
			int nonce = 0;
			using var sha256 = SHA256Managed.Create();
			do
			{
				x = new FE(sha256.ComputeHash(Encoding.UTF8.GetBytes(text + nonce)));
				nonce++;
			}
			while (!GE.TryCreateXOVariable(x, true, out ge));

			return new GroupElement(ge);
		}

		private static readonly Dictionary<Scalar, GroupElement> NumsCache = new Dictionary<Scalar, GroupElement>();
	}
}