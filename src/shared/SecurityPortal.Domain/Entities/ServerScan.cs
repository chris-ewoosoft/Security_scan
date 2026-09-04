using System.Security.Cryptography;
using System.Text;
using SecurityPortal.Domain.Common;
using SecurityPortal.Domain.Common.Exceptions;

namespace SecurityPortal.Domain.Entities;

public enum ServerAuthType
{
    Password = 0,
    PrivateKey = 1
}

/// <summary>Internal Linux server triage scan performed directly over SSH (host, port, credentials).</summary>
public class ServerScan : AggregateRoot
{
    public string Host { get; private set; } = string.Empty;
    public int Port { get; private set; } = 22;
    public string Username { get; private set; } = string.Empty;
    public ServerAuthType AuthType { get; private set; } = ServerAuthType.Password;

    /// <summary>AES-GCM encrypted secret (password, or private key PEM, depending on AuthType).</summary>
    public string SecretCipher { get; private set; } = string.Empty;

    /// <summary>AES-GCM encrypted private key passphrase (PrivateKey auth only, optional).</summary>
    public string? PassphraseCipher { get; private set; }

    public ScanStatus Status { get; private set; } = ScanStatus.Queued;
    public Guid? CreatedByUserId { get; private set; }
    public Guid? OrganizationId { get; private set; }
    public DateTime? StartedAt { get; private set; }
    public DateTime? CompletedAt { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string? Summary { get; private set; }

    /// <summary>JSON array of check findings produced by the SSH triage.</summary>
    public string? FindingsJson { get; private set; }

    /// <summary>Raw detector evidence retained only for the configured evidence window.</summary>
    public string? RawOutputJson { get; private set; }
    public DateTime? RawOutputExpiresAt { get; private set; }

    public string OwnerTokenHash { get; private set; } = string.Empty;

    private ServerScan() { }

    public static ServerScan Create(
        string host,
        int port,
        string username,
        ServerAuthType authType,
        string secretCipher,
        string? passphraseCipher,
        string ownerTokenHash,
        Guid? createdByUserId = null,
        Guid? organizationId = null)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new DomainException("Server IP/host is required.");
        if (string.IsNullOrWhiteSpace(username))
            throw new DomainException("SSH username is required.");
        if (port is <= 0 or > 65535)
            throw new DomainException("Invalid SSH port.");
        if (string.IsNullOrWhiteSpace(secretCipher))
            throw new DomainException("SSH password or private key is required.");
        if (string.IsNullOrWhiteSpace(ownerTokenHash))
            throw new DomainException("Scan owner token is required.");

        return new ServerScan
        {
            Host = host.Trim(),
            Port = port,
            Username = username.Trim(),
            AuthType = authType,
            SecretCipher = secretCipher,
            PassphraseCipher = passphraseCipher,
            OwnerTokenHash = ownerTokenHash,
            Status = ScanStatus.Queued
        };
    }

    public static string CreateOwnerToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public static string HashOwnerToken(string plaintext)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(plaintext.Trim()));
        return Convert.ToHexString(bytes);
    }

    public bool MatchesOwnerToken(string? plaintextToken)
    {
        if (string.IsNullOrWhiteSpace(OwnerTokenHash) || string.IsNullOrWhiteSpace(plaintextToken))
            return false;
        var actual = HashOwnerToken(plaintextToken);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(OwnerTokenHash),
            Encoding.UTF8.GetBytes(actual));
    }

    public void MarkRunning()
    {
        if (Status is ScanStatus.Completed or ScanStatus.Cancelled)
            throw new DomainException("Cannot restart a finished scan.");

        Status = ScanStatus.Running;
        StartedAt = DateTime.UtcNow;
        ErrorMessage = null;
        SetUpdatedAt();
    }

    public void Complete(string summary, string findingsJson, string? rawOutputJson = null)
    {
        Status = ScanStatus.Completed;
        CompletedAt = DateTime.UtcNow;
        Summary = summary;
        FindingsJson = findingsJson;
        RawOutputJson = rawOutputJson;
        RawOutputExpiresAt = rawOutputJson is null ? null : DateTime.UtcNow.AddHours(48);
        SetUpdatedAt();
    }

    public bool ExpireRawOutputIfNeeded(DateTime utcNow)
    {
        if (RawOutputJson is null || RawOutputExpiresAt is null || RawOutputExpiresAt > utcNow)
            return false;

        RawOutputJson = null;
        SetUpdatedAt();
        return true;
    }

    public void Fail(string errorMessage)
    {
        Status = ScanStatus.Failed;
        CompletedAt = DateTime.UtcNow;
        ErrorMessage = errorMessage;
        SetUpdatedAt();
    }

    public void Cancel(string reason = "Scan cancelled by user.")
    {
        if (Status is ScanStatus.Completed or ScanStatus.Cancelled)
            return;

        Status = ScanStatus.Cancelled;
        CompletedAt = DateTime.UtcNow;
        Summary = reason;
        ErrorMessage = reason;
        SetUpdatedAt();
    }
}
