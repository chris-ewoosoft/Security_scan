namespace SecurityPortal.Application.Common.Interfaces;

public interface IScanSecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string cipherText);
}
