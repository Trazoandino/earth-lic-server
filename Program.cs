// Program.cs  (EarthLicServer - .NET 8, Minimal API)
// Requiere: Microsoft.NET.Sdk.Web y referencia local a libs/Portable.Licensing.dll (v1.1.0)

using System;
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

// ========== Carga de secretos/entorno ==========

// Opción A (recomendada): variable de entorno PRIVATE_KEY_PEM con el PEM completo
string? pem = Environment.GetEnvironmentVariable("PRIVATE_KEY_PEM");

// Opción B: ruta a archivo en PRIVATE_KEY_PATH (ej: /etc/secrets/private.key en Render)
string privatePem = pem ?? File.ReadAllText(Environment.GetEnvironmentVariable("PRIVATE_KEY_PATH") ?? "private.key");

// Pass/phrase con la que se generó la privada
string privatePass = Environment.GetEnvironmentVariable("PRIVATE_KEY_PASS") ?? "change-me";

// Webhook secret de Lemon (Settings → Webhooks)
string lsSecret = Environment.GetEnvironmentVariable("LS_WEBHOOK_SECRET") ?? "";

// SMTP opcional (para enviar por correo la licencia)
string smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "";
int smtpPort = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var smtpPortParsed) ? smtpPortParsed : 587;
string smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "";
string smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS") ?? "";
string fromMail = Environment.GetEnvironmentVariable("FROM_MAIL") ?? "licencias@tu-dominio.com";

// ========== Mapeo Variant → (semanas, meses, version, community) ==========
// IDs según tu listado (1..8)
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
    // Comunidad (gratis, sin expiración)
    { 1053345, (0,  0, "2023", true)  }, // Versión Libre Comunidad 2023
    { 1053346, (0,  0, "2025", true)  }, // Licencia Libre Comunidad 2025
};

// ========== App ==========

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Puerto para plataformas PaaS (Railway/Render/Heroku-like)
var port = Environment.GetEnvironmentVariable("PORT") ?? "5000";
app.Urls.Add($"http://0.0.0.0:{port}");

// --- Health check (para Render) ---
app.MapGet("/healthz", () => Results.Ok("ok"));

// --- Ping rápido ---
app.MapGet("/", () => "EarthLicServer OK");

// --- Licencia de prueba: 7 días ---
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

// --- Webhook de Lemon: order_created ---
app.MapPost("/webhooks/lemonsqueezy", async (HttpRequest req) =>
{
    using var rdr = new StreamReader(req.Body);
    var body = await rdr.ReadToEndAsync();

    // Verifica HMAC (X-Signature). Si no configuraste LS_WEBHOOK_SECRET, permite en pruebas.
    if (!VerifyHmac(body, lsSecret, req.Headers["X-Signature"].ToString()))
        return Results.Unauthorized();

    using var doc = JsonDocument.Parse(body);
    string eventName = Get(doc.RootElement, "meta.event_name") ?? "";
    if (!string.Equals(eventName, "order_created", StringComparison.OrdinalIgnoreCase))
        return Results.Ok("ignored");

    long variantId = long.Parse(Get(doc.RootElement, "data.attributes.variant_id") ?? "0");
    string email = Get(doc.RootElement, "data.attributes.user_email") ?? "cliente@correo";
    string name  = Get(doc.RootElement, "data.attributes.user_name")  ?? "Cliente";

    if (!map.TryGetValue(variantId, out var cfg))
        return Results.BadRequest($"Variant {variantId} no mapeada");

    var lic = BuildLicense(name, email, cfg.weeks, cfg.months, 0, cfg.version, cfg.community);

    // Envío opcional por correo (adjunto license.lic)
    TrySendMail(email, $"Licencia Earth Revit {cfg.version}",
        "Adjuntamos tu licencia. Guárdala en C:\\ProgramData\\Estuche\\license.lic y abre Revit.",
        lic);

    Console.WriteLine($"OK {email} -> {cfg.version} {cfg.months}m/{cfg.weeks}w community={cfg.community}");
    return Results.Ok(new { ok = true });
});

app.Run();


// ================= Helpers =================

PL.License BuildLicense(string name, string email, int weeks, int months, int days, string version, bool community)
{
    var lic = PL.License.New()
        .WithUniqueIdentifier(Guid.NewGuid())
        .As(PL.LicenseType.Standard)
        .WithProductFeatures(new Dictionary<string, string> {
            { "Apps", PRODUCT_CODE },              // tu verificador revisa "EARTH"
            { "Version", version },                // 2023 | 2025
            { "Community", community ? "true" : "false" }
        })
        .LicensedTo(name, email);

    // Comunidad = sin expiración. Si no, calcula fecha fin.
    if (!community)
    {
        DateTime expires = DateTime.UtcNow
            .AddDays(days + weeks * 7)
            .AddMonths(months);

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
    // En pruebas puedes dejar secret vacío para saltar verificación
    if (string.IsNullOrWhiteSpace(secret)) return true;
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
        mm.Attachments.Add(new Attachment(
            new MemoryStream(Encoding.UTF8.GetBytes(lic.ToString())), "license.lic"));

        using var sc = new SmtpClient(smtpHost, smtpPort)
        {
            EnableSsl = true,
            Credentials = new System.Net.NetworkCredential(smtpUser, smtpPass)
        };
        sc.Send(mm);
    }
    catch (Exception ex)
    {
        Console.WriteLine("SMTP error: " + ex.Message);
    }
}
