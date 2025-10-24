// Program.cs  (EarthLicServer – .NET 8, Minimal API)
// Requiere: Microsoft.NET.Sdk.Web y referencia local a libs/Portable.Licensing.dll (v1.1.0)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
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

// ================== SECRETS / ENTORNO ==================

string? pem = Environment.GetEnvironmentVariable("PRIVATE_KEY_PEM");
string privatePem = pem ?? File.ReadAllText(Environment.GetEnvironmentVariable("PRIVATE_KEY_PATH") ?? "private.key");
string privatePass = Environment.GetEnvironmentVariable("PRIVATE_KEY_PASS") ?? "change-me";

string lsSecret = Environment.GetEnvironmentVariable("LS_WEBHOOK_SECRET") ?? "";

// SMTP opcional
string smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "";
int smtpPort = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var p) ? p : 587;
string smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "";
string smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS") ?? "";
string fromMail = Environment.GetEnvironmentVariable("FROM_MAIL") ?? "licencias@tu-dominio.com";

// ================== MAPEO VARIANTS ==================

var map = new Dictionary<long, (int weeks, int months, string version, bool community)>
{
    // 2025
    { 1051443, (0,  3, "2025", false) },
    { 1051506, (0,  6, "2025", false) },
    { 1052828, (0, 12, "2025", false) },
    // 2023
    { 1052829, (0,  3, "2023", false) },
    { 1052830, (0,  6, "2023", false) },
    { 1052840, (0, 12, "2023", false) },
    // Comunidad (sin expiración)
    { 1053345, (0,  0, "2023", true ) },
    { 1053346, (0,  0, "2025", true ) },
};

// ================== “CLAIMS” EN MEMORIA (PROTO) ==================

var claims = new ConcurrentDictionary<string, ClaimEntry>();

record ClaimEntry(string Email, byte[] Bytes, DateTime ReadyAtUtc, DateTime ExpiresAtUtc, int MaxDownloads);

// Limpieza simple cada 10 min
var cleaner = new System.Timers.Timer(1000 * 60 * 10);
cleaner.Elapsed += (_, __) =>
{
    foreach (var kv in claims)
        if (kv.Value.ExpiresAtUtc <= DateTime.UtcNow)
            claims.TryRemove(kv.Key, out _);
};
cleaner.AutoReset = true;
cleaner.Start();

// ================== APP ==================

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var portEnv = Environment.GetEnvironmentVariable("PORT") ?? "5000";
app.Urls.Add($"http://0.0.0.0:{portEnv}");

// Health
app.MapGet("/healthz", () => Results.Ok(new { ok = true }));

// Root
app.MapGet("/", () => "EarthLicServer OK");

// Trial 7 días
app.MapGet("/trial", (HttpRequest req) =>
{
    string email = req.Query["email"].ToString();
    if (string.IsNullOrWhiteSpace(email)) email = "trial@user";

    string version = req.Query["version"].ToString();
    if (string.IsNullOrWhiteSpace(version)) version = "2025";

    var lic = BuildLicense("Trial", email, weeks: 0, months: 0, days: 7, version, community: false);
    var bytes = Encoding.UTF8.GetBytes(lic.ToString());
    return Results.File(bytes, "text/plain", $"earth-{version}-trial.lic");
});

// ===== Webhook Lemon: order_created -> genera y almacena claim =====
app.MapPost("/webhooks/lemonsqueezy", async (HttpRequest req) =>
{
    using var rdr = new StreamReader(req.Body);
    var body = await rdr.ReadToEndAsync();

    // Acepta X-Signature (normalmente minúscula en headers)
    var sig = req.Headers["X-Signature"].ToString();
    if (string.IsNullOrEmpty(sig))
        sig = req.Headers["x-signature"].ToString();

    if (!VerifyHmac(body, lsSecret, sig))
        return Results.Unauthorized();

    using var doc = JsonDocument.Parse(body);
    string eventName = Get(doc.RootElement, "meta.event_name") ?? "";
    if (!string.Equals(eventName, "order_created", StringComparison.OrdinalIgnoreCase))
        return Results.Ok("ignored");

    // Datos principales del pedido
    long variantId = long.Parse(Get(doc.RootElement, "data.attributes.variant_id") ?? "0");
    string email = Get(doc.RootElement, "data.attributes.user_email") ?? "cliente@correo";
    string name = Get(doc.RootElement, "data.attributes.user_name") ?? "Cliente";

    if (!map.TryGetValue(variantId, out var cfg))
        return Results.BadRequest($"Variant {variantId} no mapeada");

    var lic = BuildLicense(name, email, cfg.weeks, cfg.months, 0, cfg.version, cfg.community);
    var licBytes = Encoding.UTF8.GetBytes(lic.ToString());

    // OrderId robusto (prueba varias rutas del payload)
    string orderId = Get(doc.RootElement, "data.id")
                  ?? Get(doc.RootElement, "data.attributes.order_id")
                  ?? Get(doc.RootElement, "meta.custom_data.order_id")
                  ?? Guid.NewGuid().ToString();

    claims[orderId] = new ClaimEntry(
        Email: email,
        Bytes: licBytes,
        ReadyAtUtc: DateTime.UtcNow,
        ExpiresAtUtc: DateTime.UtcNow.AddDays(7),
        MaxDownloads: 3
    );

    // (Opcional) Enviar también por correo
    // TrySendMail(email, $"Licencia Earth Revit {cfg.version}",
    //     "Adjuntamos tu licencia. Guárdala en C:\\ProgramData\\Estuche\\license.lic y abre Revit.",
    //     lic);

    Console.WriteLine($"[WEBHOOK] OK {email} -> {cfg.version} {cfg.months}m/{cfg.weeks}w community={cfg.community} orderId={orderId}");
    return Results.Ok(new { ok = true });
});

// ===== Reclamo: descarga licencia si ya está lista =====
// GET /claim?order_id=...&email=...
app.MapGet("/claim", (HttpRequest req) =>
{
    var orderId = req.Query["order_id"].ToString();
    var email   = req.Query["email"].ToString();

    if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
        return Results.BadRequest("Faltan parámetros: order_id y email");

    if (!claims.TryGetValue(orderId, out var entry))
        return Results.NotFound(new { ready = false, msg = "Aún no recibimos tu pago (webhook). Reintenta en unos segundos." });

    if (!string.Equals(entry.Email, email, StringComparison.OrdinalIgnoreCase))
        return Results.Unauthorized();

    if (entry.ExpiresAtUtc <= DateTime.UtcNow)
    {
        claims.TryRemove(orderId, out _);
        return Results.StatusCode(410); // expiró
    }

    if (entry.MaxDownloads <= 0)
        return Results.StatusCode(429); // demasiadas descargas

    // Decrementa contador y entrega
    claims[orderId] = entry with { MaxDownloads = entry.MaxDownloads - 1 };
    return Results.File(entry.Bytes, "application/octet-stream", "license.lic");
});

// ===== Estado: para “polling” en tu página de Gracias =====
// GET /claim/status?order_id=...&email=...
app.MapGet("/claim/status", (HttpRequest req) =>
{
    var orderId = req.Query["order_id"].ToString();
    var email   = req.Query["email"].ToString();

    if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
        return Results.BadRequest(new { ready = false, msg = "Faltan parámetros" });

    if (!claims.TryGetValue(orderId, out var entry))
        return Results.Ok(new { ready = false });

    var ok = string.Equals(entry.Email, email, StringComparison.OrdinalIgnoreCase)
             && entry.ExpiresAtUtc > DateTime.UtcNow;

    return Results.Ok(new { ready = ok });
});

app.Run();

// ================== HELPERS ==================

PL.License BuildLicense(string name, string email, int weeks, int months, int days, string version, bool community)
{
    var l = PL.License.New()
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
        l = l.ExpiresAt(expires);
    }

    return l.CreateAndSignWithPrivateKey(privatePem, privatePass);
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
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => cur.GetRawText()
    };
}

static bool VerifyHmac(string body, string secret, string headerSig)
{
    if (string.IsNullOrWhiteSpace(secret)) return true; // en pruebas
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
