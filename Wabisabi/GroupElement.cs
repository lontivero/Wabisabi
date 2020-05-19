using System;
using NBitcoin.Secp256k1;

namespace Wabisabi
{
	public readonly struct GroupElement : IEquatable<GroupElement>
	{
		private readonly GE ge;

		public bool IsInfinity => ge.IsInfinity;
		
		public GroupElement(GE ge)
		{
			this.ge = ge;
		}

		private GroupElement(GEJ gej)
		{
			this.ge = gej.ToGroupElement();
		}

		public GroupElement Negate()
		{
			return new GroupElement(this.ge.Negate());
		}

		public byte[] ToByteArray()
		{
			Span<byte> buffer = stackalloc byte[64];
			this.ge.x.WriteToSpan(buffer);
			this.ge.y.WriteToSpan(buffer.Slice(32));
			return buffer.ToArray();
		}

		public static GroupElement operator + (in GroupElement a, in GroupElement b)
		{
			return new GroupElement(a.ge.ToGroupElementJacobian().AddVariable(b.ge, out _));
		}

		public static GroupElement operator * (in Scalar scalar, in GroupElement groupElement)
		{
			return new GroupElement(scalar * groupElement.ge);
		}

		public static bool operator == (GroupElement g, GroupElement h) => g.Equals(h);

		public static bool operator != (GroupElement g, GroupElement h)=> !g.Equals(h);

		public bool Equals(GroupElement other)
		{
			return (this.IsInfinity && other.IsInfinity)
			 	|| (this + other.Negate()).IsInfinity; //(this.ge.x == other.ge.x && this.ge.y == other.ge.y);
		}

		public override bool Equals(object obj)
		{
			if (obj is GroupElement other)
			{
				return this.Equals(other);
			}
			return false;
		}

		public override int GetHashCode()
		{
			return this.ge.GetHashCode();
		}

		public override string ToString()
		{
			return $"Hash code: {GetHashCode()} {ge.ToC("(undefined)")}";
		}
	}
}
