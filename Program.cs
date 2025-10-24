// Program.cs  (.NET 8, Minimal API clásico)
// Requiere: <Project Sdk="Microsoft.NET.Sdk.Web">  y referencia local a libs/Portable.Licensing.dll (v1.1.0)

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
using PL = Portable.Licensing;

namespace EarthLicServer;

public static class Program
{
    // ---- Constantes / estado ----
    private const string PRODUCT_CODE = "EARTH";

    // “Cola” en memoria: cuando llega el webhook guardamos lo necesario
    // para que el cliente luego reclame/descargue su licencia.
    private static readonly ConcurrentDictionary<string, ClaimInfo> Claims = new();

    // Mapa de variantes Lemon → configuración de licencia
    private static readonly Dictionary<long, (int weeks, int months, string version, bool community)> VariantMap =
        new()
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

    // Secretos de entorno (se cargan en Main)
    private static string _privatePem = "";
    private static string _privatePass = "";
    private static string _lsSecret    = "";

    // SMTP (opcional)
    private static string _smtpHost = "";
    private static int    _smtpPort = 587;
    private static string _smtpUser = "";
    private static string _smtpPass = "";
    private static string _fromMail = "licencias@tu-dominio.com";

    public static void Main(string[] args)
    {
        // ====== Carga de variables de entorno / secretos ======
        var pem = Environment.GetEnvironmentVariable("PRIVATE_KEY_PEM");
        _privatePem = pem ?? File.ReadAllText(Environment.GetEnvironmentVariable("PRIVATE_KEY_PATH") ?? "private.key");
        _privatePass = Environment.GetEnvironmentVariable("PRIVATE_KEY_PASS") ?? "change-me";
        _lsSecret    = Environment.GetEnvironmentVariable("LS_WEBHOOK_SECRET") ?? "";

        _smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "";
        _smtpPort = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var p) ? p : 587;
        _smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "";
        _smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS") ?? "";
        _fromMail = Environment.GetEnvironmentVariable("FROM_MAIL") ?? _fromMail;

        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        // Render/Heroku-like port binding
        var port = Environment.GetEnvironmentVariable("PORT") ?? "5000";
        app.Urls.Add($"http://0.0.0.0:{port}");

        // ====== Endpoints ======
        app.MapGet("/", () => Results.Text("EarthLicServer OK"));
        app.MapGet("/healthz", () => Results.Ok("ok"));

        // Trial rápido (7 días)
        app.MapGet("/trial", (HttpRequest req) =>
        {
            string email = req.Query["email"];
            if (string.IsNullOrWhiteSpace(email)) email = "trial@user";
            string version = req.Query["version"];
            if (string.IsNullOrWhiteSpace(version)) version = "2025";

            var lic = BuildLicense("Trial", email, 0, 0, 7, version, community: false);
            var bytes = Encoding.UTF8.GetBytes(lic.ToString());
            return Results.File(bytes, "text/plain", $"earth-{version}-trial.lic");
        });

        // Webhook Lemon Squeezy (order_created)
        app.MapPost("/webhooks/lemonsqueezy", async (HttpRequest req) =>
        {
            using var rdr = new StreamReader(req.Body);
            var body = await rdr.ReadToEndAsync();

            // Verificación HMAC (si secret vacío -> sin verificación, útil en pruebas)
            var headerSig = req.Headers["X-Signature"].ToString();
            if (!VerifyHmac(body, _lsSecret, headerSig))
                return Results.Unauthorized();

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            string eventName = Get(root, "meta.event_name") ?? "";
            if (!eventName.Equals("order_created", StringComparison.OrdinalIgnoreCase))
                return Results.Ok(new { ignored = true });

            long variantId = long.Parse(Get(root, "data.attributes.variant_id") ?? "0");
            string email   = Get(root, "data.attributes.user_email") ?? "cliente@correo";
            string name    = Get(root, "data.attributes.user_name") ?? "Cliente";
            string orderId = Get(root, "data.id") ?? Guid.NewGuid().ToString("N");

            if (!VariantMap.TryGetValue(variantId, out var cfg))
                return Results.BadRequest($"Variant {variantId} no mapeada");

            var key = ClaimKey(orderId, email);
            Claims[key] = new ClaimInfo(name, email, cfg.version, cfg.community, cfg.weeks, cfg.months, ready: true);

            // (Opcional) notificación por correo
            TrySendMail(email,
                $"Licencia lista: Earth Revit {cfg.version}",
                "Tu compra fue registrada. Puedes descargar tu licencia desde la página de gracias o usar el botón dentro del plugin.",
                null);

            Console.WriteLine($"[Webhook] OK order={orderId} email={email} v={cfg.version} months={cfg.months} comm={cfg.community}");
            return Results.Ok(new { ok = true });
        });

        // Consulta de estado para la página de gracias
        app.MapGet("/claim/status", (HttpRequest req) =>
        {
            string orderId = req.Query["order_id"];
            string email   = req.Query["email"];
            if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
                return Results.Json(new { ready = false });

            var key = ClaimKey(orderId, email);
            bool ready = Claims.ContainsKey(key);
            return Results.Json(new { ready });
        });

        // Descarga de la licencia (attachment)
        app.MapGet("/claim", (HttpRequest req) =>
        {
            string orderId = req.Query["order_id"];
            string email   = req.Query["email"];
            if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
                return Results.BadRequest("missing params");

            var key = ClaimKey(orderId, email);
            if (!Claims.TryGetValue(key, out var ci))
                return Results.NotFound("not ready");

            var lic = BuildLicense(ci.Name, ci.Email, ci.Weeks, ci.Months, 0, ci.Version, ci.Community);
            var bytes = Encoding.UTF8.GetBytes(lic.ToString());
            var fname = $"earth-{ci.Version}-{DateTime.UtcNow:yyyyMMdd}.lic";
            return Results.File(bytes, "text/plain", fname);
        });

        app.Run();
    }

    // ========= Helpers =========

    private static string ClaimKey(string orderId, string email)
        => $"{orderId}:{email.Trim().ToLowerInvariant()}";

    private static PL.License BuildLicense(string name, string email, int weeks, int months, int days, string version, bool community)
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

        return l.CreateAndSignWithPrivateKey(_privatePem, _privatePass);
    }

    private static string? Get(JsonElement root, string path)
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

    private static bool VerifyHmac(string body, string secret, string headerSig)
    {
        if (string.IsNullOrWhiteSpace(secret)) return true;   // en pruebas
        if (string.IsNullOrWhiteSpace(headerSig)) return false;

        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hex = BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(body)))
                          .Replace("-", "").ToLowerInvariant();
        return string.Equals(hex, headerSig, StringComparison.OrdinalIgnoreCase);
    }

    private static void TrySendMail(string to, string subject, string text, PL.License? lic)
    {
        if (string.IsNullOrWhiteSpace(_smtpHost)) return;
        try
        {
            using var mm = new MailMessage(_fromMail, to, subject, text);
            if (lic != null)
                mm.Attachments.Add(new Attachment(new MemoryStream(Encoding.UTF8.GetBytes(lic.ToString())), "license.lic"));

            using var sc = new SmtpClient(_smtpHost, _smtpPort)
            { EnableSsl = true, Credentials = new System.Net.NetworkCredential(_smtpUser, _smtpPass) };
            sc.Send(mm);
        }
        catch (Exception ex) { Console.WriteLine("SMTP error: " + ex.Message); }
    }

    private readonly record struct ClaimInfo(
        string Name, string Email, string Version, bool Community, int Weeks, int Months, bool ready);
}
