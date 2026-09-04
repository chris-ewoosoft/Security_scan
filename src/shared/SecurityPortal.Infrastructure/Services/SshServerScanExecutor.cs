using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Infrastructure.Services;

/// <summary>Runs a reduced set of internal-server triage checks over SSH (mirrors docs/internal_scan.md IOC checks).</summary>
public sealed partial class SshServerScanExecutor : IServerScanExecutor
{
    [GeneratedRegex(
        @"(nohup\s+\./bash\s+-connect|\./bash\s+-connect|wget\s+http://[0-9.]+:[0-9]+/\.bash|curl\s+http://[0-9.]+:[0-9]+/\.bash|chmod\s+\+x\s+\.bash|/usr/tmp/\.tmp|/tmp/\.sshd\.log|cat\s+\.env|curl\s.*?/api/decrypt|docker\s+container\s+restart|docker\s+restart|authorized_keys|tcpdump|dumpcap|tshark|ettercap|dsniff|netsniff|bettercap|PROMISC|LD_PRELOAD|\(deleted\))",
        RegexOptions.IgnoreCase)]
    private static partial Regex IocPattern();

    public Task<ServerScanExecutionResult> ExecuteAsync(ServerScanExecutionRequest request, CancellationToken cancellationToken = default) =>
        Task.Run(() => Execute(request, cancellationToken), cancellationToken);

    private static ServerScanExecutionResult Execute(ServerScanExecutionRequest request, CancellationToken cancellationToken)
    {
        ConnectionInfo connectionInfo;
        try
        {
            connectionInfo = BuildConnectionInfo(request);
        }
        catch (Exception ex)
        {
            return new ServerScanExecutionResult(false, $"Invalid SSH credentials: {ex.Message}", "", []);
        }

        using var client = new SshClient(connectionInfo);
        using var cancellationRegistration = cancellationToken.Register(() =>
        {
            if (client.IsConnected)
                client.Disconnect();
        });
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            client.Connect();
        }
        catch (Exception ex)
        {
            return new ServerScanExecutionResult(false, $"SSH connection failed: {ex.Message}", "", []);
        }

        try
        {
            var findings = new List<ServerScanFinding>
            {
                RunCheck(client, cancellationToken, "authorized-keys", "Authorized Keys (SSH)",
                    "cat ~/.ssh/authorized_keys 2>/dev/null || cat /root/.ssh/authorized_keys 2>/dev/null || echo '(none)'"),
                RunCheck(client, cancellationToken, "suspicious-tmp", "Suspicious Temp Directories",
                    "for d in /usr/tmp/.tmp /tmp/.tmp /var/tmp /dev/shm; do [ -d \"$d\" ] && echo \"[DIR] $d\" && ls -la \"$d\" 2>/dev/null; done"),
                RunCheck(client, cancellationToken, "bash-payload", ".bash Payload Check",
                    "for p in /usr /usr/local /usr/tmp/.tmp /tmp /var/tmp /root /home; do [ -f \"$p/.bash\" ] && echo \"[FOUND] $p/.bash\" && ls -la \"$p/.bash\"; done"),
                RunCheck(client, cancellationToken, "cron-persistence", "Cron / Persistence",
                    "{ crontab -l 2>/dev/null || echo 'no crontab'; } ; echo '---'; ls -la /etc/cron* /var/spool/cron 2>/dev/null"),
                RunCheck(client, cancellationToken, "process-check", "Running Processes (top CPU)",
                    "ps -eo pid,user,%cpu,cmd --sort=-pcpu 2>/dev/null | head -n 50"),
                RunCheck(client, cancellationToken, "process-integrity", "Process and Executable Integrity",
                    "for p in /proc/[0-9]*; do [ -r \"$p/cmdline\" ] || continue; exe=$(readlink \"$p/exe\" 2>/dev/null || true); case \"$exe\" in *'/tmp/'*|*'/var/tmp/'*|*'/dev/shm/'*|*'(deleted)'*) echo \"$p $exe\";; esac; done"),
                RunCheck(client, cancellationToken, "network-sniffer", "Network and Sniffer Indicators",
                    "printf '%s\\n' '--- interfaces ---'; ip -details link 2>/dev/null | grep -iE 'PROMISC|promiscuity' || true; printf '%s\\n' '--- capture tools ---'; command -v tcpdump dumpcap tshark ettercap dsniff netsniff-ng bettercap 2>/dev/null || true; printf '%s\\n' '--- raw sockets ---'; ss -H -A raw 2>/dev/null || true; printf '%s\\n' '--- connections ---'; ss -H -antup 2>/dev/null || netstat -antup 2>/dev/null || true"),
                RunCheck(client, cancellationToken, "sniffer-processes", "Sniffer Process Correlation",
                    "if command -v lsof >/dev/null 2>&1; then lsof -nP 2>/dev/null | grep -iE '(tcpdump|dumpcap|tshark|ettercap|dsniff|netsniff|bettercap|libpcap)' | head -n 200; fi; ps -eo pid,ppid,user,etime,cmd --no-headers 2>/dev/null | grep -iE '(tcpdump|dumpcap|tshark|ettercap|dsniff|netsniff|bettercap)' | grep -v grep || true"),
                RunCheck(client, cancellationToken, "malware-indicators", "Malware and Reverse Shell Indicators",
                    "ps -eo pid,ppid,user,etime,cmd --no-headers 2>/dev/null | grep -iE '(xmrig|kworker.*crypt|curl[^|]*\\|[[:space:]]*(ba)?sh|wget[^|]*\\|[[:space:]]*(ba)?sh|nc(\\.openbsd)? .*(-e|/bin/(ba)?sh)|socat .*exec|/dev/tcp/|base64[[:space:]]+(-d|--decode)|nohup.*(curl|wget))' | grep -v grep || true; find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -printf '%m %u %TY-%Tm-%Td %TH:%TM %p\\n' 2>/dev/null | head -n 200"),
                RunCheck(client, cancellationToken, "exfiltration-indicators", "Data Exfiltration Indicators",
                    "ps -eo pid,user,etime,cmd --no-headers 2>/dev/null | grep -iE '(mysqldump|pg_dump|mongodump|tar .*(/etc|/var/www|/home)|zip .*(/etc|/var/www|/home)|scp |rsync |curl .*(-T|--upload-file)|wget .*--post-file)' | grep -v grep || true; if command -v ss >/dev/null 2>&1; then ss -H -ntup state established 2>/dev/null; fi"),
                RunCheck(client, cancellationToken, "ssh-auth-events", "SSH Authentication Events",
                    "if command -v journalctl >/dev/null 2>&1; then journalctl -u ssh -u sshd --since '7 days ago' --no-pager -o short-iso 2>/dev/null | grep -iE 'Accepted|Failed|Invalid user|authentication failure|session opened|session closed' | tail -n 250; else grep -iE 'Accepted|Failed|Invalid user|authentication failure' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 250; fi"),
                RunCheck(client, cancellationToken, "systemd-persistence", "Systemd Persistence",
                    "systemctl list-unit-files --type=service --state=enabled 2>/dev/null; systemctl list-timers --all 2>/dev/null | head -n 100"),
                RunCheck(client, cancellationToken, "startup-persistence", "Startup and Shell Persistence",
                    "for f in /etc/rc.local /etc/profile /etc/bash.bashrc /etc/ld.so.preload; do [ -f \"$f\" ] && { echo \"--- $f ---\"; sed -n '1,160p' \"$f\"; }; done; find /root /home -maxdepth 3 -type f \\( -name '.profile' -o -name '.bashrc' -o -name '.bash_profile' \\) -print 2>/dev/null"),
                RunCheck(client, cancellationToken, "suid-files", "Unexpected SUID/SGID Files",
                    "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -printf '%m %u:%g %p\\n' 2>/dev/null | sort | head -n 200"),
                RunCheck(client, cancellationToken, "recent-files", "Recently Changed Files",
                    "find /tmp /var/tmp /dev/shm /var/www /opt -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\\n' 2>/dev/null | head -n 300"),
                RunCheck(client, cancellationToken, "package-integrity", "Debian Package Integrity",
                    "if command -v dpkg >/dev/null 2>&1; then dpkg -V 2>/dev/null | head -n 200; elif command -v debsums >/dev/null 2>&1; then debsums -s 2>/dev/null | head -n 200; else echo 'Debian package verifier unavailable'; fi"),
            };

            var iocHits = findings.Count(f => IocPattern().IsMatch(f.Detail));
            var summary = iocHits > 0
                ? $"{iocHits} check(s) matched known IOC signatures — review immediately."
                : "No known IOC signatures detected across checked paths.";

            return new ServerScanExecutionResult(true, null, summary, findings);
        }
        finally
        {
            client.Disconnect();
        }
    }

    private static ConnectionInfo BuildConnectionInfo(ServerScanExecutionRequest request)
    {
        if (request.AuthType == ServerAuthType.PrivateKey)
        {
            using var keyStream = new MemoryStream(Encoding.UTF8.GetBytes(request.Secret));
            var keyFile = string.IsNullOrEmpty(request.Passphrase)
                ? new PrivateKeyFile(keyStream)
                : new PrivateKeyFile(keyStream, request.Passphrase);
            return new ConnectionInfo(request.Host, request.Port, request.Username,
                new PrivateKeyAuthenticationMethod(request.Username, keyFile))
            {
                Timeout = TimeSpan.FromSeconds(20)
            };
        }

        var passwordAuthentication = new PasswordAuthenticationMethod(request.Username, request.Secret);
        var keyboardInteractiveAuthentication = new KeyboardInteractiveAuthenticationMethod(request.Username);
        keyboardInteractiveAuthentication.AuthenticationPrompt += (_, e) =>
        {
            foreach (var prompt in e.Prompts)
            {
                if (prompt.Request.Contains("password", StringComparison.OrdinalIgnoreCase))
                    prompt.Response = request.Secret;
            }
        };

        return new ConnectionInfo(request.Host, request.Port, request.Username,
            passwordAuthentication, keyboardInteractiveAuthentication)
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
    }

    private static ServerScanFinding RunCheck(SshClient client, CancellationToken cancellationToken, string id, string name, string command)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var cmd = client.CreateCommand(command);
            cmd.CommandTimeout = TimeSpan.FromSeconds(15);
            var output = cmd.Execute();
            var detail = string.IsNullOrWhiteSpace(output) ? "(empty)" : Truncate(output.Trim(), 4000);
            var matched = IocPattern().IsMatch(detail) || IsHighSignal(id, detail);
            var metadata = MetadataFor(id);
            var severity = matched ? metadata.HighSeverity : "info";
            var status = detail is "(empty)" or "(none)" or "docker not found" or "no crontab" ? "clean" : "reviewed";
            return new ServerScanFinding(id, name, severity, status, detail, metadata.Category,
                matched ? "medium" : "high", metadata.Recommendation, metadata.Analysis);
        }
        catch (Exception ex)
        {
            var metadata = MetadataFor(id);
            return new ServerScanFinding(id, name, "unknown", "error", $"Command failed: {ex.Message}",
                metadata.Category, "high", "Review SSH permissions and command compatibility on the target.", metadata.Analysis);
        }
    }

    private static (string Category, string HighSeverity, string Recommendation, string Analysis) MetadataFor(string id) => id switch
    {
        "authorized-keys" => ("credential-access", "high", "Review every key owner, remove unknown keys, and rotate exposed credentials.", "An unexpected SSH key can provide persistent access and enable later data theft."),
        "suspicious-tmp" or "bash-payload" or "recent-files" => ("malware", "high", "Preserve evidence, verify file origin and hash, then remove or quarantine only after approval.", "Executable or payload-like artifacts in temporary paths are consistent with malware staging or persistence."),
        "cron-persistence" or "systemd-persistence" or "startup-persistence" => ("persistence", "high", "Validate each entry against the approved baseline and disable unknown persistence after evidence capture.", "A new scheduled task or startup hook can relaunch malware after reboot or logout."),
        "process-check" or "process-integrity" => ("execution", "high", "Validate process owner, executable path, parent process, start time, hash, and package provenance.", "The process command line and executable location may indicate a reverse shell, miner, downloaded payload, or deleted binary still running."),
        "network-sniffer" => ("network-sniffing", "high", "Confirm whether capture tools, promiscuous mode, or raw sockets are authorized; inspect owning processes and outbound peers.", "Promiscuous mode or raw packet access is high risk when correlated with an unauthorized capture process or suspicious outbound connection."),
        "sniffer-processes" => ("network-sniffing", "high", "Identify the process owner and command line, verify authorization, preserve evidence, and stop capture only through the approved incident process.", "A running packet-capture tool is stronger evidence than an interface flag alone and may expose credentials or application data."),
        "malware-indicators" => ("malware", "high", "Preserve the process and file evidence, calculate hashes, isolate the host if approved, then remove or reimage through incident response.", "Reverse-shell patterns, miners, decoded shell payloads, or executable files in temporary paths are consistent with active compromise."),
        "exfiltration-indicators" => ("data-exfiltration", "high", "Map each command and established connection to a process, preserve evidence, rotate exposed secrets, and contain the destination under the approved response plan.", "Archive, database-dump, upload, or suspicious outbound activity can indicate preparation or transfer of sensitive data."),
        "ssh-auth-events" => ("account-compromise", "high", "Review source IPs and users, revoke suspicious sessions/keys, rotate credentials, and enable MFA or SSH allowlists where supported.", "Repeated failures, invalid users, or successful logins from an untrusted source may indicate credential attacks or account compromise."),
        "suid-files" => ("privilege-escalation", "high", "Compare SUID/SGID files with the approved OS baseline and investigate unexpected additions.", "Unexpected privileged binaries can provide local privilege escalation and access to protected data."),
        "package-integrity" => ("integrity", "high", "Reinstall or restore modified packages from trusted repositories after preserving evidence.", "Package verification changes may indicate tampering, persistence, or incomplete incident cleanup."),
        _ => ("host-triage", "high", "Review the evidence against the approved server baseline.", "The check produced evidence that requires comparison with the server baseline.")
    };

    private static bool IsHighSignal(string id, string detail) => id switch
    {
        "sniffer-processes" => Regex.IsMatch(detail, "tcpdump|dumpcap|tshark|ettercap|dsniff|netsniff|bettercap", RegexOptions.IgnoreCase),
        "malware-indicators" => Regex.IsMatch(detail, "xmrig|reverse shell|/dev/tcp/|nc(?:\\.openbsd)? .* -e|socat .*exec|base64.*(?:-d|--decode)", RegexOptions.IgnoreCase),
        "exfiltration-indicators" => Regex.IsMatch(detail, "mysqldump|pg_dump|mongodump|scp |rsync |--upload-file|--post-file|tar .*?/etc|tar .*?/var/www|tar .*?/home|zip .*?/etc|zip .*?/var/www|zip .*?/home", RegexOptions.IgnoreCase),
        "ssh-auth-events" => Regex.IsMatch(detail, "Failed|Invalid user|authentication failure", RegexOptions.IgnoreCase),
        _ => false
    };

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...(truncated)";
}
