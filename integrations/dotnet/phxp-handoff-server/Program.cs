using System.Net;
using System.Security.Cryptography.X509Certificates;
using PhxpHandoffServer;

const string usage = """
PHXP .NET 10 handoff server

Required:
  --cert PATH                 PEM certificate (or PHXP_CERT_PATH)
  --key PATH                  PEM private key (or PHXP_KEY_PATH)

Options:
  --http-port PORT            Ordinary HTTP port, default 5080 (PHXP_HTTP_PORT)
  --https-port PORT           Ordinary HTTPS port, default 5443 (PHXP_HTTPS_PORT)
  --project PATH              Exact phx-port project path, default cwd (PHXP_PROJECT)
  --role NAME                 phx-port role, default https (PHXP_ROLE)
  --handoff-path PATH         Override derived Unix socket (PHXP_HANDOFF_PATH)
  --cert-password VALUE       PEM key password (PHXP_CERT_PASSWORD)
  --no-handoff                Run only the ordinary HTTP/HTTPS listeners
  --help                      Show this help
""";

if (args.Contains("--help", StringComparer.Ordinal))
{
    Console.WriteLine(usage);
    return;
}

ServerOptions options;
try
{
    options = ServerOptions.Parse(args);
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception.Message);
    Console.Error.WriteLine();
    Console.Error.WriteLine(usage);
    Environment.ExitCode = 2;
    return;
}

X509Certificate2 certificate;
try
{
    certificate = options.CertificatePassword is null
        ? X509Certificate2.CreateFromPemFile(options.CertificatePath, options.PrivateKeyPath)
        : X509Certificate2.CreateFromEncryptedPemFile(
            options.CertificatePath,
            options.CertificatePassword,
            options.PrivateKeyPath);
}
catch (Exception exception)
{
    Console.Error.WriteLine($"Could not load TLS certificate: {exception.Message}");
    Environment.ExitCode = 2;
    return;
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = [],
    ApplicationName = typeof(Program).Assembly.FullName
});
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(options.HttpPort);
    kestrel.ListenAnyIP(options.HttpsPort, listen => listen.UseHttps(certificate));
});
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(certificate);
if (options.HandoffEnabled)
{
    builder.Services.AddHostedService<HandoffReceiver>();
}

var app = builder.Build();
app.Run(async context =>
{
    var peer = new IPEndPoint(
        context.Connection.RemoteIpAddress ?? IPAddress.None,
        context.Connection.RemotePort);
    var scheme = context.Request.IsHttps ? "HTTPS" : "HTTP";
    var body = $"Hello from ordinary .NET 10 {scheme}\npeer={peer}\n";
    context.Response.ContentType = "text/plain; charset=utf-8";
    await context.Response.WriteAsync(body);
});

await app.RunAsync();
