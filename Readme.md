# Lski.Encryption

A couple of simple extensions to SymmetricAlgorithm to allow the user to conveniently encrypt and decrypt strings. Available on nuget.

## Usage

```cs
var algorithm = Aes.Create();
var encryptionkey = "an encryption key (super secure password)";
var salt = "a salt to store it all uniquely";

var encrypted = await algorithm.EncryptAsync("please encrypt me", encryptionkey, salt);

// encrypted = "KmOcb2FwznQPKmJ..." // shortend for brevity

var decrypted = await algorithm.DecryptAsync(encrypted, encryptionkey, salt);

// decrypted = "please encrypt me"
```

_NB: A sensible way of using this is wrapping it in a class that be used with DI, however if you do that then remember to keep your salts different for each password, otherwise any passwords that are the same will be stored encrypted as the same value as well, making it less secure._

## Build

Although in a solution each project can be built separately.

To build all the Navigate to solution `./src` and run:

```
dotnet build
```

## Publish

Navigate to solution `./src` and run:

```
PACKAGE_VERSION=""
NUGET_KEY=""

dotnet pack -c Release -o ../packages
dotnet nuget push -s https://api.nuget.org/v3/index.json "../packages/Lski.Encryption.$PACKAGE_VERSION.nupkg" -k "$NUGET_KEY"
```
_NB: Remember to add variables above._
