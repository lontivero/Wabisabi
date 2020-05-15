﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public class Generators
	{
		public static readonly GroupElement G = new GroupElement(EC.G);

		// Generators for ke verification
		public static readonly GroupElement Gw = GroupElementFromText(nameof(Gw));
		public static readonly GroupElement Gwp = GroupElementFromText(nameof(Gwp));

		// Generators for 
		public static readonly GroupElement Gx0 = GroupElementFromText(nameof(Gx0));
		public static readonly GroupElement Gx1 = GroupElementFromText(nameof(Gx1));

		// Generators for values and serial numbers commitments
		public static readonly GroupElement Gv = GroupElementFromText(nameof(Gv));   // For M_{vi}
		public static readonly GroupElement Gs = GroupElementFromText(nameof(Gs));   // For M_{si}

		// Generators for Pedersen commitments
		public static readonly GroupElement Gg = GroupElementFromText(nameof(Gg));
		public static readonly GroupElement Gh = GroupElementFromText(nameof(Gh));
		public static readonly GroupElement GV = GroupElementFromText(nameof(GV));

		public static GroupElement GetNums(int i)
		{
			if( !NumsCache.TryGetValue(i, out var ge))
			{
				ge = GroupElementFromText(i.ToString());
				NumsCache.Add(i, ge);
			}
			return ge;
		}

		private static GroupElement GroupElementFromText(string text)
		{
			using var sha256 = SHA256Managed.Create();
			var alphaBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
			var alpha = new Scalar(alphaBytes);
			var ge = alpha * EC.G;
			while (ge.IsInfinity)
			{
				alpha = alpha.Add(Scalar.One);
				ge = alpha * EC.G;
			}
			return new GroupElement(ge.ToGroupElement());
		}

		private static readonly Dictionary<int, GroupElement> NumsCache = new Dictionary<int, GroupElement>();
	}
}