XAES-256-GCM for .NET
========

This is an implementation of XAES-256-GCM as proposed by Filippo Valsorda, for .NET 8+.

Resources:
* Original post by Filippo: https://words.filippo.io/dispatches/xaes-256-gcm/
* The XAES-256-GCM specification: https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
* Reference implementations for Go and OpenSSL: https://github.com/C2SP/C2SP/tree/main/XAES-256-GCM


# Using

```C#
byte[] key; // Assign to some key
byte[] nonce = RandomNumberGenerator.GetBytes(Xaes256Gcm.NonceSize);
byte[] plaintext = "Hello XAES-256-GCM from .NET"u8.ToArray();

using Xaes256Gcm xaes = new(key);

// Seal, or encrypt
// AAD can optionally be passed as a 3rd argument
byte[] ciphertext = xaes.Encrypt(plaintext, nonce);

// Open, or decrypt
byte[] decrypted = xaes.Decrypt(ciphertext, nonce);
```

Additional overloads that accept Span-based inputs and outputs are also available.

# Tests

Tests use inputs and outputs from the reference implementation and can be run with `dotnet test`.
