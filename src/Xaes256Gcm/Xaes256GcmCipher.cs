using System.Diagnostics;
using System.Security.Cryptography;

namespace Xaes256Gcm;

public sealed class Xaes256GcmCipher : IDisposable {

    public const int OverheadEncryption = TagSize;
    public const int NonceSize = 24;
    public const int Overhead = OverheadEncryption + NonceSize;
    public const int KeySize = 32;

    private const int BlockSize = 16;
    private const int MaxPlaintextSize = int.MaxValue - Overhead;
    private const int TagSize = 16;
    private const int GcmNonceSize = 12;

    private ICryptoTransform? _transform;
    private readonly byte[] _k1;

    public Xaes256GcmCipher(ReadOnlySpan<byte> key) {
        if (key.Length != KeySize) {
            throw new ArgumentException(ExceptionText.InvalidKeyLength, nameof(key));
        }

        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;

#if NET10_0_OR_GREATER
        aes.SetKey(key);
#else
        aes.Key = key.ToArray();
#endif
        _transform = aes.CreateEncryptor();
        _k1 = InitializeK1(_transform);
    }

    public Xaes256GcmCipher(byte[] key) {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize) {
            throw new ArgumentException(ExceptionText.InvalidKeyLength, nameof(key));
        }

        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        _transform = aes.CreateEncryptor(key, null);
        _k1 = InitializeK1(_transform);
    }

    private static byte[] InitializeK1(ICryptoTransform aes) {
        byte[] k1 = new byte[BlockSize];
        int written = aes.TransformBlock(k1, 0, BlockSize, k1, 0);

        // We should always get a whole block back. Otherwise it indicates a bug in the runtime.
        if (written != BlockSize) {
            throw new CryptographicException();
        }

        byte msb = 0;

        unchecked {
            for (int i = k1.Length - 1; i >= 0; i--) {
                byte msbC = msb;
                msb = (byte)(k1[i] >> 7);
                k1[i] = (byte)((k1[i] << 1) | msbC);
            }

            k1[BlockSize - 1] ^= (byte)(msb * 0b10000111);
        }

        return k1;
    }

    public byte[] Encrypt(byte[] plaintext, byte[] nonce, byte[]? additionalData = default) {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(nonce);
        ThrowIfPlaintextTooLarge(plaintext);
        ThrowIfNonceSizeIncorrect(nonce);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        byte[] destination = new byte[plaintext.Length + OverheadEncryption];
        EncryptCore(plaintext, nonce, destination, additionalData);
        return destination;
    }

    public int Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ThrowIfPlaintextTooLarge(plaintext);
        ThrowIfNonceSizeIncorrect(nonce);
        ThrowIfDestinationTooSmall(destination, plaintext.Length + OverheadEncryption);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        int ciphertextLength = plaintext.Length + OverheadEncryption;
        EncryptCore(plaintext, nonce, destination[..ciphertextLength], additionalData);
        return ciphertextLength;
    }

    public byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[]? additionalData = null) {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);
        ThrowIfCiphertextTooSmall(ciphertext);
        ThrowIfNonceSizeIncorrect(nonce);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        byte[] destination = new byte[ciphertext.Length - OverheadEncryption];
        DecryptCore(ciphertext, nonce, destination, additionalData);
        return destination;
    }

    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ThrowIfCiphertextTooSmall(ciphertext);
        ThrowIfNonceSizeIncorrect(nonce);

        int plaintextLength = ciphertext.Length - OverheadEncryption;
        ThrowIfDestinationTooSmall(destination, plaintextLength);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        DecryptCore(ciphertext, nonce, destination[..plaintextLength], additionalData);
        return plaintextLength;
    }

    private void EncryptCore(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData) {
        Debug.Assert(nonce.Length == NonceSize);
        Debug.Assert(destination.Length == plaintext.Length + OverheadEncryption);

        byte[] key = DeriveKey(nonce[..GcmNonceSize]);
        ReadOnlySpan<byte> n = nonce[GcmNonceSize..];

        using AesGcm gcm = new(key, tagSizeInBytes: TagSize);
        gcm.Encrypt(n, plaintext, destination[..^TagSize], destination[^TagSize..], additionalData);
    }

    private void DecryptCore(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData) {
        Debug.Assert(nonce.Length == NonceSize);
        Debug.Assert(destination.Length == ciphertext.Length - OverheadEncryption);

        byte[] key = DeriveKey(nonce[..GcmNonceSize]);
        ReadOnlySpan<byte> n = nonce[GcmNonceSize..];

        using AesGcm gcm = new(key, tagSizeInBytes: TagSize);
        gcm.Decrypt(n, ciphertext[..^TagSize], ciphertext[^TagSize..], destination, additionalData);
    }

    private byte[] DeriveKey(ReadOnlySpan<byte> nonce) {
        Debug.Assert(_transform is not null);

        byte[] m1m2 = [0, 1, 0x58, 0, ..nonce, 0, 2, 0x58, 0, ..nonce];
        XorInPlace(m1m2.AsSpan(0, BlockSize), _k1);
        XorInPlace(m1m2.AsSpan(BlockSize, BlockSize), _k1);
        _transform.TransformBlock(m1m2, 0, m1m2.Length, m1m2, 0);
        return m1m2;
    }

    private static void XorInPlace(Span<byte> destination, ReadOnlySpan<byte> other) {
        Debug.Assert(destination.Length == other.Length);

        for (int i = 0; i < destination.Length; i++) {
            destination[i] ^= other[i];
        }
    }

    private static void ThrowIfPlaintextTooLarge(ReadOnlySpan<byte> plaintext) {
        if (plaintext.Length > MaxPlaintextSize) {
            throw new ArgumentException(ExceptionText.ExceededMaxPlaintextSize, nameof(plaintext));
        }
    }

    private static void ThrowIfCiphertextTooSmall(ReadOnlySpan<byte> ciphertext) {
        if (ciphertext.Length < TagSize) {
            throw new ArgumentException(ExceptionText.CiphertextTooSmall, nameof(ciphertext));
        }
    }

    private static void ThrowIfNonceSizeIncorrect(ReadOnlySpan<byte> nonce) {
        if (nonce.Length != NonceSize) {
            throw new ArgumentException(ExceptionText.InvalidNonceLength, nameof(nonce));
        }
    }

    private static void ThrowIfDestinationTooSmall(Span<byte> destination, int requiredSize) {
        if (destination.Length < requiredSize) {
            throw new ArgumentException(ExceptionText.DestinationTooSmall, nameof(destination));
        }
    }

    public void Dispose() {
        _transform?.Dispose();
        _transform = null;
    }
}
