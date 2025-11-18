using System.Diagnostics;
using System.Security.Cryptography;

namespace Xaes256Gcm;

/// <summary>
///   Implements the XAES-256-GCM algorithm.
/// </summary>
/// <remarks>
///   <para>The XAES-256-GCM algorithm is specified by <see href="https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md" />.</para>
///   <para>
///     Instances of this object are not thread safe. Callers must ensure instances are only ever accessed exclusively by
///     a single thread.
///   </para>
/// </remarks>
public sealed class Xaes256GcmCipher : IDisposable {

    /// <summary>
    ///   The overhead of encrypting a plaintext, in bytes.
    /// </summary>
    public const int OverheadEncryption = TagSize;

    /// <summary>
    ///   The size of the nonce, in bytes.
    /// </summary>
    public const int NonceSize = 24;

    /// <summary>
    ///   The overhead of sealing a plaintext, in bytes.
    /// </summary>
    public const int Overhead = OverheadEncryption + NonceSize;

    /// <summary>
    ///   The size of the key, in bytes.
    /// </summary>
    public const int KeySize = 32;

    private const int BlockSize = 16;
    private const int MaxPlaintextSize = int.MaxValue - Overhead;
    private const int TagSize = 16;
    private const int GcmNonceSize = 12;

    private ICryptoTransform? _transform;
    private readonly byte[] _k1;

    /// <summary>
    ///   Creates a new instance of <see cref="Xaes256GcmCipher"/>.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <exception cref="ArgumentException">
    ///   <paramref name="key"/> is not exactly <see cref="KeySize"/> bytes.
    /// </exception>
    /// <exception cref="PlatformNotSupportedException">
    ///   The current platform does not support AES.
    /// </exception>
    public Xaes256GcmCipher(ReadOnlySpan<byte> key) {
        if (key.Length != KeySize) {
            throw new ArgumentException(ExceptionText.InvalidKeyLength, nameof(key));
        }

        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;

#if NET10_0_OR_GREATER
        aes.SetKey(key);
#else
        aes.Key = key.ToArray();
#endif
        _transform = aes.CreateEncryptor();
        _k1 = InitializeK1(_transform);
    }

    /// <inheritdoc cref="Xaes256GcmCipher(ReadOnlySpan{byte})"/>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="key"/> is <see langword="null"/>.
    /// </exception>
    public Xaes256GcmCipher(byte[] key) {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize) {
            throw new ArgumentException(ExceptionText.InvalidKeyLength, nameof(key));
        }

        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        _transform = aes.CreateEncryptor(key, null);
        _k1 = InitializeK1(_transform);
    }

    private static byte[] InitializeK1(ICryptoTransform transform) {
        byte[] k1 = new byte[BlockSize];
        int written = transform.TransformBlock(k1, 0, BlockSize, k1, 0);

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

    /// <summary>
    ///   Encrypts a plaintext using the current key and specified nonce, with optional additional data.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce">The nonce to use.</param>
    /// <param name="additionalData">Additional data to authenticate as part of the encryption.</param>
    /// <returns>A byte array containing the ciphertext.</returns>
    /// <remarks>
    ///   The ciphertext's length will be the length of <paramref name="plaintext"/> plus <see cref="OverheadEncryption"/>.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="plaintext"/> or <paramref name="nonce"/> is <see langword="null" />.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="plaintext"/> is too long to encrypt.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes.</para>
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
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

    /// <summary>
    ///   Encrypts a plaintext using the current key and specified nonce, with optional additional data.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce">The nonce to use.</param>
    /// <param name="destination">The buffer to receive the ciphertext.</param>
    /// <param name="additionalData">Additional data to authenticate as part of the encryption.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="plaintext"/> is too long to encrypt.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="destination"/> is too small to receive the ciphertext.</para>
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public int Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ThrowIfPlaintextTooLarge(plaintext);
        ThrowIfNonceSizeIncorrect(nonce);
        ThrowIfDestinationTooSmall(destination, plaintext.Length + OverheadEncryption);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        int ciphertextLength = plaintext.Length + OverheadEncryption;
        EncryptCore(plaintext, nonce, destination[..ciphertextLength], additionalData);
        return ciphertextLength;
    }

    /// <summary>
    ///   Decrypts a ciphertext using the current key and specified nonce, with optional additional data.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="nonce">The nonce to use.</param>
    /// <param name="additionalData">The additional data to authenticate that was used as part of encryption.</param>
    /// <returns>A byte array containing the plaintext.</returns>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="ciphertext"/> or <paramref name="nonce"/> is <see langword="null" />.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="ciphertext"/> is too small to contain authenticated data.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes.</para>
    /// </exception>
    /// <exception cref="AuthenticationTagMismatchException">
    ///   The authentication tag does not validate the ciphertext and additional data.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[]? additionalData = null) {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);
        ThrowIfCiphertextTooSmall(ciphertext, OverheadEncryption);
        ThrowIfNonceSizeIncorrect(nonce);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        byte[] destination = new byte[ciphertext.Length - OverheadEncryption];
        DecryptCore(ciphertext, nonce, destination, additionalData);
        return destination;
    }

    /// <summary>
    ///   Decrypts a ciphertext using the current key and specified nonce, with optional additional data.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="nonce">The nonce to use.</param>
    /// <param name="destination">The buffer to receive the plaintext.</param>
    /// <param name="additionalData">The additional data to authenticate that was used as part of encryption.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="ciphertext"/> is too small to contain authenticated data.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="destination"/> is too small to receive the plaintext.</para>
    /// </exception>
    /// <exception cref="AuthenticationTagMismatchException">
    ///   The authentication tag does not validate the ciphertext and additional data.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ThrowIfCiphertextTooSmall(ciphertext, OverheadEncryption);
        ThrowIfNonceSizeIncorrect(nonce);

        int plaintextLength = ciphertext.Length - OverheadEncryption;
        ThrowIfDestinationTooSmall(destination, plaintextLength);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        DecryptCore(ciphertext, nonce, destination[..plaintextLength], additionalData);
        return plaintextLength;
    }

    /// <summary>
    ///   Seals, or encrypts, a plaintext, with optional additional data.
    /// </summary>
    /// <param name="plaintext">The plaintext to seal.</param>
    /// <param name="additionalData">Additional data to authenticate as part of the encryption.</param>
    /// <returns>A byte array representing the sealed and encrypted data.</returns>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="plaintext"/> is too long to encrypt.</para>
    /// </exception>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="plaintext"/> is <see langword="null" />.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    /// <remarks>
    ///   Sealing performs the same encryption as <see cref="Encrypt(byte[], byte[], byte[])"/>, however the nonce is
    ///   automatically generated from a secure random number generator and prepended to the ciphertext.
    /// </remarks>
    public byte[] Seal(byte[] plaintext, byte[]? additionalData = default) {
        ArgumentNullException.ThrowIfNull(plaintext);
        ThrowIfPlaintextTooLarge(plaintext);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        byte[] destination = new byte[plaintext.Length + Overhead];
        ReadOnlySpan<byte> nonce = Helpers.FillCsprng(destination, 0, NonceSize);
        Span<byte> ciphertext = destination.AsSpan(NonceSize);
        EncryptCore(plaintext, nonce, ciphertext, additionalData);
        return destination;
    }

    /// <summary>
    ///   Seals, or encrypts, a plaintext, with optional additional data.
    /// </summary>
    /// <param name="plaintext">The plaintext to seal.</param>
    /// <param name="destination">The buffer to receive the sealed data.</param>
    /// <param name="additionalData">Additional data to authenticate as part of the encryption.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="plaintext"/> is too long to encrypt.</para>
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    /// <remarks>
    ///   Sealing performs the same encryption as
    ///   <see cref="Encrypt(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte})"/>, however the
    ///   nonce is automatically generated from a secure random number generator and prepended to the ciphertext.
    /// </remarks>
    public int Seal(ReadOnlySpan<byte> plaintext, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ThrowIfPlaintextTooLarge(plaintext);
        ThrowIfDestinationTooSmall(destination, plaintext.Length + Overhead);
        ObjectDisposedException.ThrowIf(_transform is null, this);
        Span<byte> nonce = destination[..NonceSize];
        Span<byte> ciphertext = destination.Slice(NonceSize, plaintext.Length + OverheadEncryption);

        Helpers.FillCsprng(nonce);
        EncryptCore(plaintext, nonce, ciphertext, additionalData);
        return plaintext.Length + Overhead;
    }

    /// <summary>
    ///   Opens, or decrypts, a ciphertext, with optional additional data.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to open.</param>
    /// <param name="additionalData">The additional data to authenticate that was used as part of sealing.</param>
    /// <returns>The decrypted plaintext data.</returns>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="ciphertext"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///   <paramref name="ciphertext"/> is too small to contain authenticated data.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    /// <exception cref="AuthenticationTagMismatchException">
    ///   The authentication tag does not validate the ciphertext and additional data.
    /// </exception>
    public byte[] Open(byte[] ciphertext, byte[]? additionalData = default) {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ThrowIfCiphertextTooSmall(ciphertext, Overhead);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        ReadOnlySpan<byte> nonce = ciphertext.AsSpan(0, NonceSize);
        ReadOnlySpan<byte> plainCiphertext = ciphertext.AsSpan(NonceSize);

        byte[] destination = new byte[ciphertext.Length - Overhead];
        DecryptCore(plainCiphertext, nonce, destination, additionalData);
        return destination;
    }

    /// <summary>
    ///   Opens, or decrypts, a ciphertext, with optional additional data.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to open.</param>
    /// <param name="destination">The buffer to receive the plaintext.</param>
    /// <param name="additionalData">The additional data to authenticate that was used as part of sealing.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="ciphertext"/> is too small to contain authenticated data.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="destination"/> is too small to receive the plaintext data.</para>
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    /// <exception cref="AuthenticationTagMismatchException">
    ///   The authentication tag does not validate the ciphertext and additional data.
    /// </exception>
    public int Open(ReadOnlySpan<byte> ciphertext, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ThrowIfCiphertextTooSmall(ciphertext, Overhead);

        int plaintextSize = ciphertext.Length - Overhead;
        ThrowIfDestinationTooSmall(destination, plaintextSize);
        ObjectDisposedException.ThrowIf(_transform is null, this);

        ReadOnlySpan<byte> nonce = ciphertext[..NonceSize];
        ReadOnlySpan<byte> plainCiphertext = ciphertext[NonceSize..];
        DecryptCore(plainCiphertext, nonce, destination[..plaintextSize], additionalData);
        return plaintextSize;
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

    private static void ThrowIfCiphertextTooSmall(ReadOnlySpan<byte> ciphertext, int size) {
        if (ciphertext.Length < size) {
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

    /// <summary>
    ///   Disposes of the current instance and releases all resources.
    /// </summary>
    /// <remarks>
    ///   The instance must not be used after it has been disposed.
    /// </remarks>
    public void Dispose() {
        _transform?.Dispose();
        _transform = null;
        Array.Clear(_k1, 0, _k1.Length);
    }
}
