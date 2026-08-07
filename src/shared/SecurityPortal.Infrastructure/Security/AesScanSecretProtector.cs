using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using SecurityPortal.Application.Common.Interfaces;

namespace SecurityPortal.Infrastructure.Security;

/// <summary>AES-GCM protector for scan target passwords stored in config_json.</summary>
public sealed class AesScanSecretProtector : IScanSecretProtector
{
    private readonly byte[] _key;

    public AesScanSecretProtector(IConfiguration configuration)
    {
        var configured = configuration["ScanSecrets:Key"];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            try
            {
                _key = Convert.FromBase64String(configured.Trim());
            }
            catch (FormatException)
            {
                _key = SHA256.HashData(Encoding.UTF8.GetBytes(configured.Trim()));
            }
        }
        else
        {
            var fallback = configuration["Jwt:SecretKey"] ?? "SecurityPortal-Dev-ScanSecret-Key";
            _key = SHA256.HashData(Encoding.UTF8.GetBytes(fallback));
        }

        if (_key.Length is not (16 or 24 or 32))
            _key = SHA256.HashData(_key);

        var env = configuration["ASPNETCORE_ENVIRONMENT"]
                  ?? configuration["DOTNET_ENVIRONMENT"]
                  ?? "Production";
        var isDev = env.Equals("Development", StringComparison.OrdinalIgnoreCase);
        if (!isDev && string.IsNullOrWhiteSpace(configured))
        {
            throw new InvalidOperationException(
                "ScanSecrets:Key must be configured in non-Development environments (do not rely on JWT/dev fallback).");
        }
    }

    public string Protect(string plaintext)
    {
        ArgumentException.ThrowIfNullOrEmpty(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plain, cipher, tag);
        var payload = new byte[nonce.Length + tag.Length + cipher.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, payload, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipher, 0, payload, nonce.Length + tag.Length, cipher.Length);
        return Convert.ToBase64String(payload);
    }

    public string Unprotect(string cipherText)
    {
        ArgumentException.ThrowIfNullOrEmpty(cipherText);
        var payload = Convert.FromBase64String(cipherText);
        if (payload.Length < 12 + 16)
            throw new CryptographicException("Invalid cipher payload.");

        var nonce = payload.AsSpan(0, 12);
        var tag = payload.AsSpan(12, 16);
        var cipher = payload.AsSpan(28);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }
}
