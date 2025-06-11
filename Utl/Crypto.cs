using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

public static class AesHelper {
    public static byte[] DecryptAesCbcNoPadding(byte[] key, byte[] data) {
        using (Aes aes = Aes.Create()) {
            aes.Key = key;
            aes.IV = new byte[16]; // zero IV
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None; // must match Java's "NoPadding"

            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(data))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var result = new MemoryStream()) {
                cs.CopyTo(result);
                return result.ToArray();
            }
        }
    }
}