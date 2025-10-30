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
using Microsoft.Extensions.DependencyInjection; // <-- necesario para AddCors

// Alias para evitar conflicto con System.ComponentModel.License
using PL = Portable.Licensing;

const string PRODUCT_CODE = "EARTH";

// ================== Config / secretos ==================

// Clave privada para firmar licencias.
// Preferimos PRIVATE_KEY_PEM en entorno (Render); como fallback, PRIVATE_KEY_PATH o "private.key".
string? pem = Environment.GetEnvironmentVariable("PRIVATE_KEY_PEM");
string privatePem = !string.IsNullOrWhiteSpace(pem)
    ? pem!
    : File.ReadAllText(Environment.GetEnvironmentVariable("PRIVATE_KEY_PATH") ?? "private.key");

string privatePass = Environment.GetEnvironmentVariable("PRIVATE_KEY_PASS") ?? "change-me";

// Webhook secret de Lemon (Settings → Webhooks)
string lsSecret = Environment.GetEnvironmentVariable("LS_WEBHOOK_SECRET") ?? "";

// SMTP opcional (para enviar por correo la licencia al cliente)
string smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "";
int smtpPort = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var p) ? p : 587;
string smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "";
string smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS") ?? "";
string fromMail = Environment.GetEnvironmentVariable("FROM_MAIL") ?? "licencias@tu-dominio.com";

// ========== Mapeo Variant → (semanas, meses, version, community) ==========
// OJO: estos Variant IDs deben ser los IDs reales de tus variantes en Lemon Squeezy
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

    // Comunidad / gratis
    { 1053345, (0,  0, "2023", true)  }, // Libre Comunidad 2023
    { 1053346, (0,  0, "2025", true)  }, // Libre Comunidad 2025
};

// ========== Store en memoria para “claims” ==========
var claims = new ConcurrentDictionary<string, ClaimState>();
static string ClaimKey(string orderId, string email) => $"{orderId}::{email}".ToLowerInvariant();

// Limpieza básica de claims (cada 30 min elimina >12h)
using var cleanupTimer = new System.Threading.Timer(_ =>
{
    var cutoff = DateTime.UtcNow.AddHours(-12);
    foreach (var kv in claims)
    {
        if (kv.Value.Claim.CreatedUtc < cutoff)
            claims.TryRemove(kv.Key, out ClaimState _);
    }
}, null, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30));

// ========== App / Hosting ==========

var builder = WebApplication.CreateBuilder(args);

// ---- CORS ----
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy
            .AllowAnyOrigin()  // en prod puedes restringir: .WithOrigins("https://trazoandino.github.io")
            .AllowAnyHeader()
            .AllowAnyMethod()
    );
});

var app = builder.Build();

// habilita CORS
app.UseCors();

// Evita cachearse respuestas dinámicas
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    await next();
});

// Render te pasa el puerto en $PORT
var portEnv = Environment.GetEnvironmentVariable("PORT") ?? "5000";
app.Urls.Add($"http://0.0.0.0:{portEnv}");

//
// ---------- ENDPOINTS -----------
//

// ===== Helpers de auth admin (const-time) =====
static bool IsAdmin(HttpRequest req)
{
    // token por query o por header
    string token = req.Query["token"];
    if (string.IsNullOrEmpty(token))
        token = req.Headers["x-admin-token"];

    string env = Environment.GetEnvironmentVariable("ADMIN_TOKEN") ?? string.Empty;
    if (string.IsNullOrEmpty(env) || string.IsNullOrEmpty(token)) return false;

    var a = Encoding.UTF8.GetBytes(env);
    var b = Encoding.UTF8.GetBytes(token);
    if (a.Length != b.Length) return false;
    return CryptographicOperations.FixedTimeEquals(a, b);
}

// --- DEV: emitir licencia ad-hoc en minutos (solo admin) ---
app.MapGet("/dev/lic", (HttpRequest req) =>
{
    if (!IsAdmin(req))
        return Results.Unauthorized();

    string email   = string.IsNullOrWhiteSpace(req.Query["email"])   ? "dev@user" : req.Query["email"].ToString();
    string version = string.IsNullOrWhiteSpace(req.Query["version"]) ? "2025"     : req.Query["version"].ToString();

    // límite de seguridad (máx 120 min)
    int minutes = 2;
    if (int.TryParse(req.Query["minutes"], out var m) && m > 0 && m <= 120) minutes = m;

    var lic = BuildLicenseMinutes("Dev Flash", email, minutes, version, community: false);
    var bytes = Encoding.UTF8.GetBytes(lic.ToString());
    return Results.File(bytes, "application/octet-stream", "license.lic");
});

// (Opcional) Debug: confirma si ADMIN_TOKEN está definido (no revela el valor)
app.MapGet("/dev/debug/admin-token", () =>
{
    var val = Environment.GetEnvironmentVariable("ADMIN_TOKEN");
    return Results.Ok(new { hasAdminToken = !string.IsNullOrEmpty(val), length = val?.Length ?? 0 });
});

// Salud / ping / wake
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
    return Results.File(bytes, "application/octet-stream", "license.lic");
});

// -------- Webhook de Lemon Squeezy: order_created ----------
app.MapPost("/webhooks/lemonsqueezy", async (HttpRequest req) =>
{
    string body = await new StreamReader(req.Body).ReadToEndAsync();

    // Verifica firma HMAC del webhook si configuras el secret en Lemon
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
    {
        // ignoramos otros eventos
        return Results.Ok(new { ignored = eventName });
    }

    // Extraer datos clave de la orden
    long variantId = long.Parse(Get(root, "data.attributes.variant_id") ?? "0");

    string orderId = Get(root, "data.id")
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
        OrderId:     orderId,
        Email:       email,
        Name:        name,
        VariantId:   variantId,
        Version:     cfg.version,
        Community:   cfg.community,
        Weeks:       cfg.weeks,
        Months:      cfg.months,
        Days:        0,
        CreatedUtc:  DateTime.UtcNow
    );

    // Creamos/actualizamos el estado en memoria
    var state = claims.GetOrAdd(ClaimKey(orderId, email), _ => new ClaimState(claim));

    // Generar la licencia real firmada
    var lic = BuildLicense(
        name,
        email,
        cfg.weeks,
        cfg.months,
        0,
        cfg.version,
        cfg.community
    );

    // Guardamos para que /claim la pueda servir
    state.LicenseText = lic.ToString();
    state.Ready = true;

    Console.WriteLine($"[Webhook] READY order={orderId} email={email} ver={cfg.version} months={cfg.months} community={cfg.community}");

    // (Opcional) enviar por correo adjuntando la licencia
    TrySendMail(
        email,
        $"Licencia Earth Revit {cfg.version}",
        "Adjuntamos tu licencia. Guárdala en C:\\ProgramData\\Estuche\\license.lic y abre Revit.",
        lic
    );

    // Respondemos 200 OK al webhook
    return Results.Ok(new { ok = true });
});

// -------- Polling desde gracias.html --------

// 1) /claim/status => para saber si la licencia ya está lista
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

// 2) /claim => si está lista, devuelve el archivo license.lic como descarga
app.MapGet("/claim", (HttpRequest req) =>
{
    string orderId = req.Query["order_id"].ToString() ?? "";
    string email   = req.Query["email"].ToString() ?? "";

    if (string.IsNullOrWhiteSpace(orderId) || string.IsNullOrWhiteSpace(email))
        return Results.BadRequest(new { error = "missing_params" });

    if (!claims.TryGetValue(ClaimKey(orderId, email), out var state)
        || !state.Ready
        || string.IsNullOrEmpty(state.LicenseText))
        return Results.NotFound(new { error = "not_ready" });

    byte[] bytes = Encoding.UTF8.GetBytes(state.LicenseText);
    string fileName = "license.lic"; // nombre final que el usuario va a guardar

    return Results.File(
        bytes,
        "application/octet-stream",
        fileName,
        enableRangeProcessing: false
    );
});

app.Run();


// ================= Helpers =================

// Construye y firma la licencia usando Portable.Licensing y tu clave privada
PL.License BuildLicense(string name, string email, int weeks, int months, int days, string version, bool community)
{
    var lic = PL.License
        .New()
        .WithUniqueIdentifier(Guid.NewGuid())
        .As(PL.LicenseType.Standard)
        .WithProductFeatures(new Dictionary<string, string> {
            { "Apps", PRODUCT_CODE },
            { "Version", version },
            { "Community", community ? "true" : "false" }
        })
        .LicensedTo(name, email);

    // Si NO es community/free, le ponemos fecha de expiración
    if (!community)
    {
        DateTime expires = DateTime.UtcNow
            .AddDays(days + weeks * 7)
            .AddMonths(months);

        lic = lic.ExpiresAt(expires);
    }

    // Firmar con nuestra private.key + passphrase
    return lic.CreateAndSignWithPrivateKey(privatePem, privatePass);
}

// Overload para minutos (para /dev/lic)
PL.License BuildLicenseMinutes(string name, string email, int minutes, string version, bool community)
{
    var lic = PL.License
        .New()
        .WithUniqueIdentifier(Guid.NewGuid())
        .As(PL.LicenseType.Standard)
        .WithProductFeatures(new Dictionary<string, string> {
            { "Apps", PRODUCT_CODE },
            { "Version", version },
            { "Community", community ? "true" : "false" }
        })
        .LicensedTo(name, email);

    if (!community)
        lic = lic.ExpiresAt(DateTime.UtcNow.AddMinutes(minutes));

    return lic.CreateAndSignWithPrivateKey(privatePem, privatePass);
}

// helper para navegar JSON del webhook sin pelearse con niveles
static string? Get(JsonElement root, string path)
{
    var cur = root;
    foreach (var part in path.Split('.'))
    {
        if (!cur.TryGetProperty(part, out cur))
            return null;
    }

    return cur.ValueKind switch
    {
        JsonValueKind.String => cur.GetString(),
        JsonValueKind.Number => cur.GetRawText(),
        JsonValueKind.True   => "true",
        JsonValueKind.False  => "false",
        _ => cur.GetRawText()
    };
}

// Validar la firma HMAC que manda Lemon Squeezy en X-Signature
static bool VerifyHmac(string body, string secret, string headerSig)
{
    // En pruebas locales puedes dejar secret vacío para que acepte todo
    if (string.IsNullOrWhiteSpace(secret)) return true;
    if (string.IsNullOrWhiteSpace(headerSig)) return false;

    using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var hex = BitConverter
        .ToString(h.ComputeHash(Encoding.UTF8.GetBytes(body)))
        .Replace("-", "")
        .ToLowerInvariant();

    return string.Equals(hex, headerSig, StringComparison.OrdinalIgnoreCase);
}

// Enviar correo con la licencia adjunta (opcional)
void TrySendMail(string to, string subject, string text, PL.License lic)
{
    if (string.IsNullOrWhiteSpace(smtpHost)) return;

    try
    {
        using var mm = new MailMessage(fromMail, to, subject, text);
        mm.Attachments.Add(new Attachment(
            new MemoryStream(Encoding.UTF8.GetBytes(lic.ToString())),
            "license.lic"
        ));

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


// ========= Tipos: al FINAL (para evitar CS8803 con top-level statements) =========

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
    DateTime CreatedUtc
);

class ClaimState
{
    public Claim Claim { get; init; }
    public bool Ready { get; set; }
    public string? LicenseText { get; set; }

    public ClaimState(Claim c)
    {
        Claim = c;
    }
}
