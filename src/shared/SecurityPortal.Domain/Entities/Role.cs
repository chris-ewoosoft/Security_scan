using SecurityPortal.Domain.Common;

namespace SecurityPortal.Domain.Entities;

public class Role : BaseEntity
{
    public string Name { get; private set; } = string.Empty;
    public string? Description { get; private set; }
    public bool IsSystem { get; private set; }

    private readonly List<RolePermission> _rolePermissions = [];
    public IReadOnlyList<RolePermission> RolePermissions => _rolePermissions.AsReadOnly();

    private Role() { }

    public static Role Create(string name, string? description = null, bool isSystem = false) =>
        new() { Name = name, Description = description, IsSystem = isSystem };

    public void GrantPermission(Guid permissionId)
    {
        if (_rolePermissions.Any(rp => rp.PermissionId == permissionId)) return;
        _rolePermissions.Add(RolePermission.Create(Id, permissionId));
    }

    public void RevokePermission(Guid permissionId)
    {
        var rp = _rolePermissions.FirstOrDefault(x => x.PermissionId == permissionId);
        if (rp is not null) _rolePermissions.Remove(rp);
    }

    public static class SystemRoles
    {
        public const string Admin = "Admin";
        public const string SecurityEngineer = "SecurityEngineer";
        public const string Viewer = "Viewer";
    }
}

public class Permission : BaseEntity
{
    public string Name { get; private set; } = string.Empty;   // "projects:write"
    public string Resource { get; private set; } = string.Empty;
    public string Action { get; private set; } = string.Empty;

    private Permission() { }

    public static Permission Create(string resource, string action) =>
        new() { Name = $"{resource}:{action}", Resource = resource, Action = action };

    public static class All
    {
        public const string ProjectsRead = "projects:read";
        public const string ProjectsWrite = "projects:write";
        public const string ProjectsDelete = "projects:delete";
        public const string AssetsRead = "assets:read";
        public const string AssetsWrite = "assets:write";
        public const string ScansRead = "scans:read";
        public const string ScansWrite = "scans:write";
        public const string FindingsRead = "findings:read";
        public const string FindingsWrite = "findings:write";
        public const string ReportsRead = "reports:read";
        public const string ReportsWrite = "reports:write";
        public const string UsersRead = "users:read";
        public const string UsersWrite = "users:write";
    }
}

public class UserRole : BaseEntity
{
    public Guid UserId { get; private set; }
    public Guid RoleId { get; private set; }
    public Role? Role { get; private set; }

    private UserRole() { }

    public static UserRole Create(Guid userId, Guid roleId) =>
        new() { UserId = userId, RoleId = roleId };
}

public class RolePermission : BaseEntity
{
    public Guid RoleId { get; private set; }
    public Guid PermissionId { get; private set; }
    public Permission? Permission { get; private set; }

    private RolePermission() { }

    public static RolePermission Create(Guid roleId, Guid permissionId) =>
        new() { RoleId = roleId, PermissionId = permissionId };
}
