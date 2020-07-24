using System;
using System.Collections.Generic;
using System.Linq;

namespace Lski.Encryption
{
	/// <summary>
	/// A ridiculously simply set of assertions to ensure parameters are valid.
	/// </summary>
	internal static class Assert
	{
		public static void Check(bool valid, string paramName, string message = "Argument was invalid")
		{
			if (!valid) { throw new ArgumentNullException(paramName, message); }
		}

		public static void NotNull<T>(T obj, string paramName)
		{
			if (obj == null) { throw new ArgumentNullException(paramName); }
		}

		public static void NotNullOrEmpty(string str, string paramName)
		{
			NotNull(str, paramName);
			if (str == string.Empty) { throw new ArgumentException(paramName); }
		}

		public static void NotNullOrEmpty<T>(IEnumerable<T> items, string paramName)
		{
			if (items == null) { throw new ArgumentNullException(paramName); }
			if (!items.Any()) { throw new ArgumentException(paramName); }
		}
	}
}