// Program.cs  (EarthLicServer - .NET 8, Minimal API)
// Requiere: Microsoft.NET.Sdk.Web y referencia a libs/Portable.Licensing.dll (v1.1.0)

using System.Collections.Concurrent;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

// Alias para evitar conflicto con System.ComponentModel.License
using PL = Portable.Licensing;

const string PRODUCT_CODE = "EARTH";

// ================== Config / secretos ==================
string? pem = Environment.GetEnvironmentVariable("PRIVATE_KEY_PEM");
string privatePem = pem ?? File.ReadAllText(Environment.GetEnvironmentVariable("PRIVATE_KEY_PATH") ?? "private.key");
string privatePass = Environment.GetEnvironmentVariable("PRIVATE_KEY_PASS") ?? "change-me";

// Webhook secret de Lemon (Settings → Webhooks)
string lsSecret = Environment.GetEnvironmentVariable("LS_WEBHOOK_SECRET") ?? "";

// SMTP opcional (para enviar por correo)
string smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "";
int smtpPort = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var p) ? p : 587;
string smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "";
string smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS") ?? "";
string fromMail = Environment.GetEnvironmentVariable("FROM_MAIL") ?? "licencias@tu-dominio.com";

// ========== Mapeo Variant → (semanas, meses, version, community) ==========
var map = new Dictionary<long, (int weeks, int months, string version, bool community)>
{
    // Revit 2025
    { 1051443, (0,  3, "2025", false) }, // 3 meses
    { 1051506, (0,  6, "2025", false) }, // 6 meses
    { 1052828, (0, 12, "2025", false) }, // 1 año
    // Revit 2023
    { 1052829, (0,  3, "2023", false) }, // 3 meses
    { 1052830, (0,  6, "2023", false) }, // 6 meses
    { 1052840, (0, 12, "2023", false) }, // 1 año
    // Comunidad
    { 1053345, (0,  0, "2023", true)  }, // Libre Comunidad 2023
    { 1053346, (0,  0, "2025", true)  }, // Libre Comunidad 2025
};

// ========== Store en memoria para “claims” ==========
var claims = new ConcurrentDictionary<string, ClaimState>();
static string ClaimKey(string orderId, string email) => $"{orderId}::{email}".ToLowerInvariant();

// Limpieza básica (evita acumular en memoria)
using var cleanupTimer = new System.Threading.Timer(_ =>
{
    var cutoff = DateTime.UtcNow.AddHours(-12);
    foreach (var kv in claims)
        if (kv.Value.Claim.CreatedUtc < cutoff)
            claims.TryRemove(kv.Key, out ClaimState _);
}, null, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30));

// ========== App ==========
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Evita cachearse respuestas dinámicas (por si algún proxy mete mano)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    await next();
});

var portEnv = Environment.GetEnvironmentVariable("PORT") ?? "5000";
app.Urls.Add($"http://0.0.0.0:{portEnv}");

// Salud / ping / wake (útiles para precalentar)
app.MapGet("/healthz", () => Results.Ok(new { ok = true }));
app.MapGet("/ping",     () => Results.Ok(new { ok = true, ts = DateTime.UtcNow }));
app.MapGet("/wake",     () => Results.Ok(new { ok = true, ts = DateTime.UtcNow }));

// Raíz
app.MapGet("/", () => "EarthLicServer OK");

// -------- Licencia de prueba (7 días) ----------
app.MapGet("/trial", (HttpRequest req) =>
{
    string email = req.Query["email"].ToString();
    if (string.IsNullOrWhiteSpace(email)) email = "trial@user";

    string version = req.Query["version"].ToString();
    if (string.IsNullOrWhiteSpace(version)) version = "2025";

    var lic = BuildLicense("Trial", email, 0, 0, 7, version, community: false);
    var bytes = Encoding.UTF8.GetBytes(lic.ToString());
    // Forzamos nombre license.lic para que el usuario solo mueva el archivo.
    return Results.File(bytes, "application/octet-stream", "license.lic");
});

// -------- Webhook de Lemon: order_created ----------
app.MapPost("/webhooks/lemonsqueezy", async (HttpRequest req) =>
{
    string body = await new StreamReader(req.Body).ReadToEndAsync();

    // Firma HMAC
    var headerSig = req.Headers.TryGetValue("X-Signature", out var sv) ? sv.ToString() : "";
    if (!VerifyHmac(body, lsSecret, headerSig))
    {
        Console.WriteLine("[Webhook] Firma inválida");
        return Results.Unauthorized();
    }

    using var doc = JsonDocument.Parse(body);
    var root = doc.RootElement;

    var eventName = Get(root, "meta.event_name") ?? "";
    Console.WriteLine($"[Webhook] event = {eventName}");
    if (!string.Equals(eventName, "order_created", StringComparison.OrdinalIgnoreCase))
        return Results.Ok(new { ignored = eventName });

    // Datos claves del pedido
    long variantId = long.Parse(Get(root, "data.attributes.variant_id") ?? "0");
    string orderId  = Get(root, "data.id")
                      ?? Get(root, "data.attributes.order_number")
                      ?? Guid.NewGuid().ToString("N");

    string email = Get(root, "data.attributes.user_email") ?? "cliente@correo";
    string name  = Get(root, "data.attributes.user_name")  ?? "Cliente";

    if (!map.TryGetValue(variantId, out var cfg))
    {
        Console.WriteLine($"[Webhook] Variant {variantId} NO mapeada");
        return Results.BadRequest(new { error = "variant_not_mapped", variantId });
    }

    var claim = new Claim(
        OrderId:  orderId,
        Email:    email,
        Name:     name,
        VariantId:variantId,
        Version:  cfg.version,
        Community:cfg.community,
        Weeks:    cfg.weeks,
        Months:   cfg.months,
        Days:     0,
        CreatedUtc: DateTime.UtcNow
    );

    var state = claims.GetOrAdd(ClaimKey(orderId, email), _ => new ClaimState(claim));

    // Genera licencia y marca lista
    var lic = BuildLicense(name, email, cfg.weeks, cfg.months, 0, cfg.version, cfg.community);
    state.LicenseText = lic.ToString();
    state.Ready = true;

    Console.WriteLine($"[Webhook] READY order={orderId} email={email} ver={cfg.version} months={cfg.months} community={cfg.community}");

    // (Opcional) correo con adjunto
    TrySendMail(email, $"Licencia Earth Revit {cfg.version}",
        "Adjuntamos tu licencia. Guárdala en C:\\ProgramData\\Estuche\\license.lic y abre Revit.",
        lic);

    return Results.Ok(new { ok = true });
});

// -------- Polling desde gracias.html --------
app.MapGet("/claim/status", (HttpRequest req) =>
{
    string orderId = req.Query["order_id"].ToString() ?? "";
    string email   = req.Query["email"].ToString() ?? "";

    if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
        return Results.BadRequest(new { ready = false, error = "missing_params" });

    if (claims.TryGetValue(ClaimKey(orderId, email), out var state))
        return Results.Ok(new { ready = state.Ready });

    return Results.Ok(new { ready = false });
});

app.MapGet("/claim", (HttpRequest req) =>
{
    string orderId = req.Query["order_id"].ToString() ?? "";
    string email   = req.Query["email"].ToString() ?? "";

    if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
        return Results.BadRequest(new { error = "missing_params" });

    if (!claims.TryGetValue(ClaimKey(orderId, email), out var state) || !state.Ready || string.IsNullOrEmpty(state.LicenseText))
        return Results.NotFound(new { error = "not_ready" });

    byte[] bytes = Encoding.UTF8.GetBytes(state.LicenseText);
    string fileName = "license.lic"; // nombre final
    return Results.File(bytes, "application/octet-stream", fileName, enableRangeProcessing: false);
});

app.Run();

// ================= Helpers =================

PL.License BuildLicense(string name, string email, int weeks, int months, int days, string version, bool community)
{
    var lic = PL.License.New()
        .WithUniqueIdentifier(Guid.NewGuid())
        .As(PL.LicenseType.Standard)
        .WithProductFeatures(new Dictionary<string, string> {
            { "Apps", PRODUCT_CODE },
            { "Version", version },
            { "Community", community ? "true" : "false" }
        })
        .LicensedTo(name, email);

    if (!community)
    {
        DateTime expires = DateTime.UtcNow.AddDays(days + weeks * 7).AddMonths(months);
        lic = lic.ExpiresAt(expires);
    }

    return lic.CreateAndSignWithPrivateKey(privatePem, privatePass);
}

static string? Get(JsonElement root, string path)
{
    var cur = root;
    foreach (var part in path.Split('.'))
        if (!cur.TryGetProperty(part, out cur)) return null;

    return cur.ValueKind switch
    {
        JsonValueKind.String => cur.GetString(),
        JsonValueKind.Number => cur.GetRawText(),
        JsonValueKind.True   => "true",
        JsonValueKind.False  => "false",
        _ => cur.GetRawText()
    };
}

static bool VerifyHmac(string body, string secret, string headerSig)
{
    if (string.IsNullOrWhiteSpace(secret)) return true;   // útil en pruebas
    if (string.IsNullOrWhiteSpace(headerSig)) return false;

    using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var hex = BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(body)))
                         .Replace("-", "").ToLowerInvariant();
    return string.Equals(hex, headerSig, StringComparison.OrdinalIgnoreCase);
}

void TrySendMail(string to, string subject, string text, PL.License lic)
{
    if (string.IsNullOrWhiteSpace(smtpHost)) return;
    try
    {
        using var mm = new MailMessage(fromMail, to, subject, text);
        mm.Attachments.Add(new Attachment(new MemoryStream(Encoding.UTF8.GetBytes(lic.ToString())), "license.lic"));
        using var sc = new SmtpClient(smtpHost, smtpPort)
        { EnableSsl = true, Credentials = new System.Net.NetworkCredential(smtpUser, smtpPass) };
        sc.Send(mm);
    }
    catch (Exception ex) { Console.WriteLine("SMTP error: " + ex.Message); }
}

// ========= Tipos: al FINAL (para evitar CS8803) =========
record Claim(
    string OrderId,
    string Email,
    string Name,
    long VariantId,
    string Version,
    bool Community,
    int Weeks,
    int Months,
    int Days,
    DateTime CreatedUtc);

class ClaimState
{
    public Claim Claim { get; init; }
    public bool Ready { get; set; }
    public string? LicenseText { get; set; }
    public ClaimState(Claim c) { Claim = c; }
}
