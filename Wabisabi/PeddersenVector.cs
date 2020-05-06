using System;
using System.Collections.Generic;
using NBitcoin.Secp256k1;

namespace Wabisabi
{	
	public class PedersenVector : IGroupElement
	{
		private readonly List<IGroupElement> _list = new List<IGroupElement>();
		private GEJ _cachedGEJ = GEJ.Infinity;

		public void Add(IGroupElement ge)
		{
			_list.Add(ge);
			_cachedGEJ = _cachedGEJ.AddVariable(ge.ToGroupElement(), out _);
		}

		public GE ToGroupElement()
		{
			return _cachedGEJ.ToGroupElement();
		}
	} 
}
