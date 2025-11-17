using System.Security.Cryptography;

namespace Xaes256Gcm;

internal static class Helpers {
#if !NET
    private static readonly RandomNumberGenerator _csprng = new RNGCryptoServiceProvider();
#endif

    internal static ReadOnlySpan<byte> FillCsprng(byte[] buffer, int offset, int length) {
#if NET
        Span<byte> destination = buffer.AsSpan(offset, length);
        RandomNumberGenerator.Fill(destination);
        return destination;
#else
        _csprng.GetBytes(buffer, offset, length);
        return buffer.AsSpan(offset, length);
#endif
    }

    internal static void FillCsprng(Span<byte> buffer) {
#if NET
        RandomNumberGenerator.Fill(buffer);
#else
        byte[] tmp = new byte[buffer.Length];
        _csprng.GetBytes(tmp);
        tmp.AsSpan().CopyTo(buffer);
#endif
    }
}
