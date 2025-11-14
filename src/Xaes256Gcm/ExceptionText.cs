using System.Runtime.Serialization;

internal static class ExceptionText {
    internal static string ExceededMaxPlaintextSize => "The plaintext size exceeds the maximum limit";
    internal static string InvalidKeyLength => "Key must be exactly 32 bytes in size.";
    internal static string InvalidNonceLength => "Nonce must be exactly 24 bytes in size.";
    internal static string DestinationTooSmall => "The destination is too small.";
    internal static string CiphertextTooSmall => "The ciphertext is too small.";
}
