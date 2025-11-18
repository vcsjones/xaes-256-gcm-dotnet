using System.Security.Cryptography;
using TestVector = (byte[] Key, byte[] Nonce, byte[] Plaintext, byte[] Ciphertext, byte[] Aad);

namespace Xaes256Gcm.Tests;

public static class Xaes256GcmTests {
    private static byte[] ZeroKey => field ??= new byte[Xaes256GcmCipher.KeySize];
    private static byte[] ZeroNonce => field ??= new byte[Xaes256GcmCipher.NonceSize];
    private static byte[] ZeroCiphertext => field ??= [0xFE, 0x62, 0x02, 0x4A, 0x33, 0x49, 0xC0, 0x6A, 0x33, 0xAF, 0xDA, 0x22, 0xA1, 0x33, 0x98, 0x1B];
    private static byte[] OneCiphertext => field ??= [0x2D, 0x01, 0x37, 0xD1, 0x9A, 0xB3, 0xEE, 0x4C, 0x46, 0xCA, 0x4D, 0xEC, 0x7D, 0x31, 0x39, 0x50, 0xC2];

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_EncryptDecrypt_Span(TestVector testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key.AsSpan());
        Span<byte> ciphertext = new byte[testVector.Plaintext.Length + Xaes256GcmCipher.OverheadEncryption + 256];
        int written = xaes.Encrypt(testVector.Plaintext.AsSpan(), testVector.Nonce.AsSpan(), ciphertext, testVector.Aad.AsSpan());
        Assert.Equal(testVector.Ciphertext, ciphertext[..written]);
        Assert.Equal(testVector.Ciphertext.Length, written);

        Span<byte> decrypted = new byte[testVector.Plaintext.Length + 256];
        written = xaes.Decrypt(ciphertext[..written], testVector.Nonce.AsSpan(), decrypted, testVector.Aad.AsSpan());
        Assert.Equal(testVector.Plaintext, decrypted[..written]);
        Assert.Equal(testVector.Plaintext.Length, written);
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_EncryptDecrypt_Array(TestVector testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key);
        byte[] ciphertext = xaes.Encrypt(testVector.Plaintext, testVector.Nonce, testVector.Aad);
        Assert.Equal(testVector.Ciphertext, ciphertext);

        byte[] decrypted = xaes.Decrypt(ciphertext, testVector.Nonce, testVector.Aad);
        Assert.Equal(testVector.Plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Open_Array(TestVector testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key);
        byte[] opened = xaes.Open([..testVector.Nonce, ..testVector.Ciphertext], testVector.Aad);
        Assert.Equal(testVector.Plaintext, opened);
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Open_Span(TestVector testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key);
        byte[] destination = new byte[testVector.Plaintext.Length];

        // Exact
        int written = xaes.Open([..testVector.Nonce, ..testVector.Ciphertext], destination, testVector.Aad);
        Assert.Equal(testVector.Plaintext, destination);
        Assert.Equal(testVector.Plaintext.Length, written);

        // Oversized
        destination = new byte[testVector.Plaintext.Length + 256];
        written = xaes.Open([..testVector.Nonce, ..testVector.Ciphertext], destination, testVector.Aad);
        Assert.Equal(testVector.Plaintext, destination.AsSpan(0, written));
        Assert.Equal(testVector.Plaintext.Length, written);
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Decrypt_Span_Tampered(TestVector testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key.AsSpan());

        byte[] tamperedCiphertext = testVector.Ciphertext.AsSpan().ToArray();
        FlipRandomBit(tamperedCiphertext);
        byte[] buffer = new byte[testVector.Plaintext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            xaes.Decrypt(tamperedCiphertext, testVector.Nonce, buffer.AsSpan(), testVector.Aad));
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Decrypt_Array_Tampered(TestVector testVector) {
        Xaes256GcmCipher xaes = new(testVector.Key.AsSpan());

        byte[] tamperedCiphertext = testVector.Ciphertext.AsSpan().ToArray();
        FlipRandomBit(tamperedCiphertext);
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            xaes.Decrypt(tamperedCiphertext, testVector.Nonce, testVector.Aad));
    }

    [Fact]
    public static void Ctor_ArgValidation_Null() {
        Assert.Throws<ArgumentNullException>("key", static () => new Xaes256GcmCipher(null));
    }

    [Fact]
    public static void Encrypt_ArgValidation_Null() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        Assert.Throws<ArgumentNullException>("plaintext", () => xaes.Encrypt(null, ZeroNonce));
        Assert.Throws<ArgumentNullException>("nonce", () => xaes.Encrypt([], null));
    }

    [Fact]
    public static void Encrypt_ArgValidation_InvalidNonceSize() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        Assert.Throws<ArgumentException>("nonce", () => xaes.Encrypt([], ZeroNonce.AsSpan()[..^1].ToArray()));
        Assert.Throws<ArgumentException>("nonce", () => xaes.Encrypt([], [..ZeroNonce, 0]));

        byte[] buffer = new byte[Xaes256GcmCipher.OverheadEncryption];
        Assert.Throws<ArgumentException>("nonce", () => xaes.Encrypt([], ZeroNonce.AsSpan()[..^1], buffer.AsSpan()));
        Assert.Throws<ArgumentException>("nonce", () => xaes.Encrypt([], [..ZeroNonce, 0], buffer.AsSpan()));
    }

    [Fact]
    public static void Encrypt_ArgValidation_DestinationTooSmall() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        byte[] buffer = new byte[Xaes256GcmCipher.OverheadEncryption - 1];
        Assert.Throws<ArgumentException>("destination", () => xaes.Encrypt([], ZeroNonce, buffer.AsSpan()));
    }

    [Fact]
    public static void Decrypt_ArgValidation_Null() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        Assert.Throws<ArgumentNullException>("ciphertext", () => xaes.Decrypt(null, ZeroNonce));
        Assert.Throws<ArgumentNullException>("nonce", () => xaes.Decrypt([], null));
    }

    [Fact]
    public static void Decrypt_ArgValidation_InvalidNonceSize() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        Assert.Throws<ArgumentException>("nonce", () => xaes.Decrypt(ZeroCiphertext, ZeroNonce.AsSpan()[..^1].ToArray()));
        Assert.Throws<ArgumentException>("nonce", () => xaes.Decrypt(ZeroCiphertext, [..ZeroNonce, 0]));

        byte[] buffer = [];
        Assert.Throws<ArgumentException>("nonce", () => xaes.Decrypt(ZeroCiphertext, ZeroNonce.AsSpan()[..^1], buffer.AsSpan()));
        Assert.Throws<ArgumentException>("nonce", () => xaes.Decrypt(ZeroCiphertext, [..ZeroNonce, 0], buffer.AsSpan()));
    }

    [Fact]
    public static void Decrypt_ArgValidation_DestinationTooSmall() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        byte[] buffer = new byte[OneCiphertext.Length - Xaes256GcmCipher.OverheadEncryption - 1];
        Assert.Throws<ArgumentException>("destination", () => xaes.Decrypt(OneCiphertext, ZeroNonce, buffer.AsSpan()));
    }

    [Fact]
    public static void Seal_ArgumentValidation_Null() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        Assert.Throws<ArgumentNullException>(() => xaes.Seal(null));
    }

    [Fact]
    public static void Seal_UniqueNonce_Array() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        byte[] first = xaes.Seal([]);
        byte[] second = xaes.Seal([]);
        Assert.NotEqual(first.AsSpan(0, Xaes256GcmCipher.NonceSize).ToArray(), second.AsSpan(0, Xaes256GcmCipher.NonceSize).ToArray());
    }

    [Fact]
    public static void Seal_UniqueNonce_Span() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        byte[] first = new byte[Xaes256GcmCipher.Overhead];
        byte[] second = new byte[Xaes256GcmCipher.Overhead];
        _ = xaes.Seal([], first.AsSpan());
        _ = xaes.Seal([], second.AsSpan());
        Assert.NotEqual(first.AsSpan(0, Xaes256GcmCipher.NonceSize).ToArray(), second.AsSpan(0, Xaes256GcmCipher.NonceSize).ToArray());
    }

    [Fact]
    public static void SealOpenRoundtrip_Array() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        byte[] plaintext = "sealed data"u8.ToArray();
        byte[] aad = "additional data"u8.ToArray();
        byte[] sealedData = xaes.Seal(plaintext, aad);
        byte[] opened = xaes.Open(sealedData, aad);
        Assert.Equal(plaintext, opened);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(256)]
    public static void SealOpenRoundtrip_Span(int oversize) {
        Xaes256GcmCipher xaes = new(ZeroKey);
        byte[] plaintext = "sealed data"u8.ToArray();
        byte[] aad = "additional data"u8.ToArray();

        byte[] destination = new byte[plaintext.Length + Xaes256GcmCipher.Overhead + oversize];
        int written = xaes.Seal(plaintext, destination, aad);
        Assert.Equal(plaintext.Length + Xaes256GcmCipher.Overhead, written);

        written = xaes.Open(destination.AsSpan(0, written), destination, aad);
        Assert.Equal(plaintext.Length, written);
        Assert.Equal(plaintext, destination.AsSpan(0, written));
    }

    [Fact]
    public static void UseAfterDispose() {
        Xaes256GcmCipher xaes = new(ZeroKey);
        xaes.Dispose();
        xaes.Dispose(); // No-op for secondary dispose.
        byte[] destination = new byte[Xaes256GcmCipher.Overhead];
        Assert.Throws<ObjectDisposedException>(() => xaes.Encrypt([], ZeroNonce));
        Assert.Throws<ObjectDisposedException>(() => xaes.Encrypt([], ZeroNonce, destination.AsSpan()));
        Assert.Throws<ObjectDisposedException>(() => xaes.Decrypt(ZeroCiphertext, ZeroNonce));
        Assert.Throws<ObjectDisposedException>(() => xaes.Decrypt(ZeroCiphertext, ZeroNonce, destination.AsSpan()));
        Assert.Throws<ObjectDisposedException>(() => xaes.Seal([]));
        Assert.Throws<ObjectDisposedException>(() => xaes.Seal([], destination.AsSpan()));
        Assert.Throws<ObjectDisposedException>(() => xaes.Open([..ZeroNonce, ..ZeroCiphertext]));
        Assert.Throws<ObjectDisposedException>(() => xaes.Open([..ZeroNonce, ..ZeroCiphertext], destination.AsSpan()));
    }

#if NET9_0_OR_GREATER
    [Theory]
    [InlineData(10_000, "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939")]
    [InlineData(1_000_000, "2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15")]
    public static void TestAccumulated(int iterations, string expected) {
        const long OpenSSL_3_3 = 0x30300000L;

        if (!Shake128.IsSupported || (OperatingSystem.IsLinux() && SafeEvpPKeyHandle.OpenSslVersion < OpenSSL_3_3)) {
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

    public static TheoryData<TestVector> TestVectors =>  [
        (KeyOf(0x01), "ABCDEFGHIJKLMNOPQRSTUVWX"u8.ToArray(), "XAES-256-GCM"u8.ToArray(), Convert.FromHexString("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"), null),
        (KeyOf(0x03), "ABCDEFGHIJKLMNOPQRSTUVWX"u8.ToArray(), "XAES-256-GCM"u8.ToArray(), Convert.FromHexString("986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"), "c2sp.org/XAES-256-GCM"u8.ToArray())
    ];

    private static byte[] KeyOf(byte value) {
        byte[] key = new byte[Xaes256GcmCipher.KeySize];
        key.AsSpan().Fill(value);
        return key;
    }

    private static void FlipRandomBit(Span<byte> input) {
#if NET
        int index = Random.Shared.Next(0, input.Length);
#else
        int index = new Random().Next(0, input.Length);
#endif
        input[index] = (byte)(input[index] ^ 0b_10000000);
    }
}
