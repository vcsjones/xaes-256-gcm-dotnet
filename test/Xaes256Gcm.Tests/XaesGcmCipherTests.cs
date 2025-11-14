#if NET9_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace Xaes256Gcm.Tests;

public static class Xaes256GcmTests {
    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Span((byte[] Key, byte[] Nonce, byte[] Plaintext, byte[] Ciphertext, byte[] Aad) testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key.AsSpan());
        Span<byte> ciphertext = new byte[testVector.Plaintext.Length + Xaes256GcmCipher.OverheadEncryption];
        xaes.Encrypt(testVector.Plaintext.AsSpan(), testVector.Nonce.AsSpan(), ciphertext, testVector.Aad.AsSpan());
        Assert.Equal(testVector.Ciphertext, ciphertext);

        Span<byte> decrypted = new byte[testVector.Plaintext.Length];
        xaes.Decrypt(ciphertext, testVector.Nonce.AsSpan(), decrypted, testVector.Aad.AsSpan());
        Assert.Equal(testVector.Plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Array((byte[] Key, byte[] Nonce, byte[] Plaintext, byte[] Ciphertext, byte[] Aad) testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key);
        byte[] ciphertext = xaes.Encrypt(testVector.Plaintext, testVector.Nonce, testVector.Aad);
        Assert.Equal(testVector.Ciphertext, ciphertext);

        byte[] decrypted = xaes.Decrypt(ciphertext, testVector.Nonce, testVector.Aad);
        Assert.Equal(testVector.Plaintext, decrypted);
    }

#if NET9_0_OR_GREATER
    [Theory]
    [InlineData(10_000, "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939")]
    [InlineData(1_000_000, "2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15")]
    public static void TestAccumulated(int iterations, string expected) {
        if (!Shake128.IsSupported || (OperatingSystem.IsLinux() && SafeEvpPKeyHandle.OpenSslVersion < 0x30300000L)) {
            Assert.Skip("Platform does not support SHAKE128.");
        }

        using Shake128 s = new();
        using Shake128 d = new();

        for (int i = 0; i < iterations; i++) {
            byte[] key = s.Read(Xaes256GcmCipher.KeySize);
            byte[] nonce = s.Read(Xaes256GcmCipher.NonceSize);
            byte[] lenByte;
            lenByte = s.Read(1);
            byte[] plaintext = s.Read(lenByte[0]);
            s.Read(lenByte);
            byte[] aad = s.Read(lenByte[0]);

            using Xaes256GcmCipher xaes = new(key);
            byte[] ciphertext = xaes.Encrypt(plaintext, nonce, aad);
            byte[] decrypted = xaes.Decrypt(ciphertext, nonce, aad);
            Assert.Equal(plaintext, decrypted);
            d.AppendData(ciphertext);
        }

        Assert.Equal(expected, Convert.ToHexStringLower(d.GetHashAndReset(32)));
    }
#endif

    public static TheoryData<(byte[] Key, byte[] Nonce, byte[] Plaintext, byte[] Ciphertext, byte[] Aad)> TestVectors =>  [
        (KeyOf(0x01), "ABCDEFGHIJKLMNOPQRSTUVWX"u8.ToArray(), "XAES-256-GCM"u8.ToArray(), Convert.FromHexString("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"), null),
        (KeyOf(0x03), "ABCDEFGHIJKLMNOPQRSTUVWX"u8.ToArray(), "XAES-256-GCM"u8.ToArray(), Convert.FromHexString("986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"), "c2sp.org/XAES-256-GCM"u8.ToArray())
    ];

    private static byte[] KeyOf(byte value) {
        byte[] key = new byte[Xaes256GcmCipher.KeySize];
        key.AsSpan().Fill(value);
        return key;
    }
}
