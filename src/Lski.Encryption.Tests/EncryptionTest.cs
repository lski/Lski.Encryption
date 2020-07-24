using FluentAssertions;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Lski.Encryption.Tests
{
	public class EncryptionTest
	{
		private readonly ITestOutputHelper _output;

		public EncryptionTest(ITestOutputHelper output)
		{
			this._output = output;
		}

		[Fact]
		public async Task Encrypt_Correctly()
		{
			var encryptor = Aes.Create();
			var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

			var encrypted = await encryptor.EncryptAsync("Hello", "World", salt);

			_output.WriteLine($"Encrypted {encrypted}");

			encrypted.Should().NotBeNullOrWhiteSpace();
			encrypted.Should().Be("ihA41lsg5UkZq6Md1g4YsA==");
		}

		[Fact]
		public async Task Encrypt_And_Decrypt_Correctly()
		{
			var encryptor = Aes.Create();
			var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

			var encrypted = await encryptor.EncryptAsync("Hello", "World", salt);
			var decrypted = await encryptor.DecryptAsync(encrypted, "World", salt);

			_output.WriteLine($"Encrypted {encrypted}");
			_output.WriteLine($"Decrypted {decrypted}");

			encrypted.Should().NotBeNullOrWhiteSpace();
			encrypted.Should().Be("ihA41lsg5UkZq6Md1g4YsA==");
			decrypted.Should().NotBeNullOrWhiteSpace();
			decrypted.Should().Be("Hello");
		}

		[Fact]
		public async Task Encrypt_Incorrect_Password_Should_Not_Match()
		{
			var encryptor = Aes.Create();
			var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

			var encrypted = await encryptor.EncryptAsync("Hello", "world", salt);

			_output.WriteLine($"Encrypted {encrypted}");

			encrypted.Should().NotBeNullOrWhiteSpace();
			encrypted.Should().NotBe("ihA41lsg5UkZq6Md1g4YsA==");
		}

		[Fact]
		public async Task Encrypt_Incorrect_Salt_Should_Not_Match()
		{
			var encryptor = Aes.Create();
			var salt = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

			var encrypted = await encryptor.EncryptAsync("Hello", "World", salt);

			_output.WriteLine($"Encrypted {encrypted}");

			encrypted.Should().NotBeNullOrWhiteSpace();
			encrypted.Should().NotBe("ihA41lsg5UkZq6Md1g4YsA==");
		}

		[Fact]
		public async Task Ensure_Password_Missing_Throws_Exception()
		{
			var encryptor = Aes.Create();
			var salt = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

			Func<Task> act = async () => {
				var encrypted = await encryptor.EncryptAsync("Hello", null, salt);
			};

			var encrypted = await encryptor.Invoking(encryptor => encryptor.EncryptAsync("Hello", null, salt))
				.Should()
				.ThrowAsync<ArgumentNullException>();
		}

		[Fact]
		public async Task Blah()
		{
			var algorithm = Aes.Create();
			var encryptionkey = "an encryption key (super secure password)";
			var salt = "a salt to store it all uniquely";

			var encrypted = await algorithm.EncryptAsync("please encrypt me", encryptionkey, salt);
			_output.WriteLine(encrypted);
		}
	}
}