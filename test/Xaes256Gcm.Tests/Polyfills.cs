namespace Xaes256Gcm.Tests;

internal static class Polyfills {
    extension(Convert) {
#if !NET
        public static byte[] FromHexString(ReadOnlySpan<char> chars) {
            if (chars.IsEmpty) {
                return [];
            }

            int byteLength = Math.DivRem(chars.Length, 2, out int remainder);

            if (remainder != 0) {
                throw new InvalidOperationException("Hex input length must be a multiple of two.");
            }

            byte[] buffer = new byte[byteLength];

            for (int i = 0, j = 0; i < buffer.Length; i++, j += 2) {
                char c1 = chars[j];
                char c2 = chars[j + 1];
                int value = HexCharToInt(c2);
                value |= HexCharToInt(c1) << 4;
                buffer[i] = (byte)value;
            }

            return buffer;

            static int HexCharToInt(char c) {
                return c switch {
                    >= '0' and <= '9' => c - '0',
                    >= 'A' and <= 'F' => c - 'A' + 10,
                    >= 'a' and <= 'f' => c - 'a' + 10,
                    _ => throw new ArgumentOutOfRangeException(nameof(c)),
                };
            }
        }
#endif
    }
}
