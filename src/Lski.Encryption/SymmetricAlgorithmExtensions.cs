using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Lski.Encryption
{
	/// <summary>
	/// Extension functions to SymmetricAlgorithms for encrypting/decrypting a string value using a password and a salt passed in.
	/// </summary>
	public static class SymmetricAlgorithmExt
	{
		/// <summary>
		/// The default number of iterations used for encrypting and decrypting
		/// </summary>
		public const int DEFAULT_ITERATIONS = 1000;

		/// <summary>
		/// Decrypts a string that was encrypted using the same password, salt and <see cref="SymmetricAlgorithm"/> that created it
		/// </summary>
		/// <param name="algorithm">The SymmetricAlgorithm to encrypt with</param>
		/// <param name="text">The text that you want to decrypt</param>
		/// <param name="encryptionKey">The password that is used with the salt to encrypt/decrypt the text</param>
		/// <param name="salt">A value to make the text being encrypted unique to a same text being encrypted elsewhere (basically a prefix added to the text prior to encryption). A salt should be unique to each stored encrypted value and saved elsewhere.</param>
		/// <param name="iterations">Is the number of times the encryption is performed</param>
		public static Task<string> DecryptAsync(this SymmetricAlgorithm algorithm, string text, string encryptionKey, string salt, int iterations = DEFAULT_ITERATIONS)
		{
			Assert.NotNullOrEmpty(salt, nameof(salt));

			return algorithm.DecryptAsync(text, encryptionKey, Encoding.Unicode.GetBytes(salt), iterations);
		}

		/// <summary>
		/// Decrypts a string that was encrypted using the same password, salt and <see cref="SymmetricAlgorithm"/> that created it
		/// </summary>
		/// <param name="algorithm">The SymmetricAlgorithm to encrypt with</param>
		/// <param name="text">The text that you want to decrypt</param>
		/// <param name="encryptionKey">The password that is used with the salt to encrypt/decrypt the text</param>
		/// <param name="salt">A value to make the text being encrypted unique to a same text being encrypted elsewhere (basically a prefix added to the text prior to encryption). A salt should be unique to each stored encrypted value and saved elsewhere.</param>
		/// <param name="iterations">Is the number of times the encryption is performed</param>
		public static async Task<string> DecryptAsync(this SymmetricAlgorithm algorithm, string text, string encryptionKey, byte[] salt, int iterations = DEFAULT_ITERATIONS)
		{
			Assert.NotNull(algorithm, nameof(algorithm));
			Assert.NotNullOrEmpty(text, nameof(text));
			Assert.NotNullOrEmpty(encryptionKey, nameof(encryptionKey));
			Assert.NotNullOrEmpty(salt, nameof(salt));
			Assert.Check(iterations > 0, nameof(iterations), "There needs to be more than one iteration for encryption to happen");

			using (var rgb = new Rfc2898DeriveBytes(encryptionKey, salt, iterations))
			{
				var rgbKey = rgb.GetBytes(algorithm.KeySize >> 3);
				var rgbIV = rgb.GetBytes(algorithm.BlockSize >> 3);

				var transform = algorithm.CreateDecryptor(rgbKey, rgbIV);

				using (var buffer = new MemoryStream(Convert.FromBase64String(text)))
				{
					using (var stream = new CryptoStream(buffer, transform, CryptoStreamMode.Read))
					{
						using (var reader = new StreamReader(stream, Encoding.Unicode))
						{
							return await reader.ReadToEndAsync();
						}
					}
				}
			}
		}

		/// <summary>
		/// Encrypts a string that can also be decrypted using the same password and a salt and <see cref="SymmetricAlgorithm"/>
		/// </summary>
		/// <param name="algorithm">The SymmetricAlgorithm to encrypt with</param>
		/// <param name="value">The text that you want to encypt</param>
		/// <param name="encryptionKey">The password that is used with the salt to encrypt/decrypt the text</param>
		/// <param name="salt">A value to make the text being encrypted unique to a same text being encrypted elsewhere (basically a prefix added to the text prior to encryption). A salt should be unique to each stored encrypted value and saved elsewhere.</param>
		/// <param name="iterations">Is the number of times the encryption is performed</param>
		public static Task<string> EncryptAsync(this SymmetricAlgorithm algorithm, string value, string encryptionKey, string salt, int iterations = DEFAULT_ITERATIONS)
		{
			Assert.NotNullOrEmpty(salt, nameof(salt));

			return algorithm.EncryptAsync(value, encryptionKey, Encoding.Unicode.GetBytes(salt));
		}

		/// <summary>
		/// Encrypts a string that can also be decrypted using the same password and a salt and <see cref="SymmetricAlgorithm"/>
		/// </summary>
		/// <param name="algorithm">The SymmetricAlgorithm to encrypt with</param>
		/// <param name="value">The text that you want to encypt</param>
		/// <param name="encryptionKey">The password that is used with the salt to encrypt/decrypt the text</param>
		/// <param name="salt">A value to make the text being encrypted unique to a same text being encrypted elsewhere (basically a prefix added to the text prior to encryption). A salt should be unique to each stored encrypted value and saved elsewhere.</param>
		/// <param name="iterations">Is the number of times the encryption is performed</param>
		public static async Task<string> EncryptAsync(this SymmetricAlgorithm algorithm, string value, string encryptionKey, byte[] salt, int iterations = DEFAULT_ITERATIONS)
		{
			Assert.NotNull(algorithm, nameof(algorithm));
			Assert.NotNullOrEmpty(value, nameof(value));
			Assert.NotNullOrEmpty(encryptionKey, nameof(encryptionKey));
			Assert.NotNullOrEmpty(salt, nameof(salt));
			Assert.Check(iterations > 0, nameof(iterations), "There needs to be more than one iteration for encryption to happen");

			using (DeriveBytes rgb = new Rfc2898DeriveBytes(encryptionKey, salt, iterations))
			{
				var rgbKey = rgb.GetBytes(algorithm.KeySize >> 3);
				var rgbIV = rgb.GetBytes(algorithm.BlockSize >> 3);

				var transform = algorithm.CreateEncryptor(rgbKey, rgbIV);

				using (var buffer = new MemoryStream())
				{
					using (var stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
					{
						using (var writer = new StreamWriter(stream, Encoding.Unicode))
						{
							await writer.WriteAsync(value);
						}
					}

					return Convert.ToBase64String(buffer.ToArray());
				}
			}
		}
	}
}