using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace PhxpHandoffServer;

internal sealed record ServerOptions(
    int HttpPort,
    int HttpsPort,
    string CertificatePath,
    string PrivateKeyPath,
    string? CertificatePassword,
    string Project,
    string Role,
    string? ExplicitHandoffPath,
    bool HandoffEnabled)
{
    public string HandoffPath => ExplicitHandoffPath ?? DeriveHandoffPath(Project, Role);

    public static ServerOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var handoffEnabled = true;

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (argument == "--no-handoff")
            {
                handoffEnabled = false;
                continue;
            }

            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument '{argument}'.");
            }

            if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Missing value for '{argument}'.");
            }

            values[argument] = args[++index];
        }

        var certificatePath = Get(values, "--cert", "PHXP_CERT_PATH")
            ?? throw new ArgumentException("A PEM certificate is required via --cert or PHXP_CERT_PATH.");
        var privateKeyPath = Get(values, "--key", "PHXP_KEY_PATH")
            ?? throw new ArgumentException("A PEM private key is required via --key or PHXP_KEY_PATH.");

        return new ServerOptions(
            ParsePort(Get(values, "--http-port", "PHXP_HTTP_PORT") ?? "5080", "--http-port"),
            ParsePort(Get(values, "--https-port", "PHXP_HTTPS_PORT") ?? "5443", "--https-port"),
            Path.GetFullPath(certificatePath),
            Path.GetFullPath(privateKeyPath),
            Get(values, "--cert-password", "PHXP_CERT_PASSWORD"),
            Path.GetFullPath(Get(values, "--project", "PHXP_PROJECT") ?? Directory.GetCurrentDirectory()),
            Get(values, "--role", "PHXP_ROLE") ?? "https",
            Get(values, "--handoff-path", "PHXP_HANDOFF_PATH") is { } path
                ? Path.GetFullPath(path)
                : null,
            handoffEnabled);
    }

    public static string DeriveHandoffPath(string project, string role)
    {
        var runtimeDirectory = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (string.IsNullOrWhiteSpace(runtimeDirectory))
        {
            throw new InvalidOperationException(
                "XDG_RUNTIME_DIR is required for PHXP endpoint discovery; use --handoff-path to override it.");
        }

        var projectBytes = Encoding.UTF8.GetBytes(project);
        var roleBytes = Encoding.UTF8.GetBytes(role);
        var input = new byte[projectBytes.Length + 1 + roleBytes.Length];
        projectBytes.CopyTo(input, 0);
        roleBytes.CopyTo(input, projectBytes.Length + 1);
        var hash = Convert.ToHexStringLower(SHA256.HashData(input));
        return Path.Combine(runtimeDirectory, "phx-port", "handoff", $"{hash}.sock");
    }

    private static string? Get(
        IReadOnlyDictionary<string, string> values,
        string argument,
        string environmentVariable) =>
        values.GetValueOrDefault(argument) ?? Environment.GetEnvironmentVariable(environmentVariable);

    private static int ParsePort(string value, string name)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 0 or > 65535)
        {
            throw new ArgumentException($"{name} must be an integer from 0 through 65535.");
        }

        return port;
    }
}
