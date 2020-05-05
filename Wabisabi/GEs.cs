using System;
using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;

namespace Wabisabi
{

	public class GEs
	{
		// Generators for ke verification
		public static readonly GE Gw = GroupElementFromText(nameof(Gw));
		public static readonly GE Gwp = GroupElementFromText(nameof(Gwp));

		// Generators for 
		public static readonly GE Gx0 = GroupElementFromText(nameof(Gx0));
		public static readonly GE Gx1 = GroupElementFromText(nameof(Gx1));

		// Generators for values and serial numbers commitments
		public static readonly GE Gv = GroupElementFromText(nameof(Gv));   // For M_{vi}
		public static readonly GE Gs = GroupElementFromText(nameof(Gs));   // For M_{si}

		// Generators for Pedersen commitments
		public static readonly GE Gg = GroupElementFromText(nameof(Gg));
		public static readonly GE Gh = GroupElementFromText(nameof(Gh));
		public static readonly GE GV = GroupElementFromText(nameof(GV));


		private static GE GroupElementFromText(string text)
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
			return ge .ToGroupElement();
		}
	}
}