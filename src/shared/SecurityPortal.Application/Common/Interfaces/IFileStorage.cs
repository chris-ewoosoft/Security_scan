namespace SecurityPortal.Application.Common.Interfaces;

public interface IFileStorage
{
    Task<string> UploadAsync(string bucketName, string objectName, Stream data, string contentType, CancellationToken cancellationToken = default);
    Task<Stream> DownloadAsync(string bucketName, string objectName, CancellationToken cancellationToken = default);
    Task DeleteAsync(string bucketName, string objectName, CancellationToken cancellationToken = default);
    Task<string> GetPresignedUrlAsync(string bucketName, string objectName, int expirySeconds = 3600, CancellationToken cancellationToken = default);
    Task EnsureBucketExistsAsync(string bucketName, CancellationToken cancellationToken = default);
}
