# Web Safe Token Service
Create time sensitive encrypted tokens that are safe to transmit via query string paramteters.

## appsettings.json
```json
{
  "Encryption": {
    "Key": "DO_NOT_USE_THIS_DO_NOT_USE_THIS!" // 32 char string
  }
}
```

## Register Services
```csharp
public class Startup
{
    private readonly IConfiguration Configuration;

    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddEncryptionServices(Configuration);
    }

    public void Configure(IApplicationBuilder app, IHostingEnvironment env)
    {
        app.UseMiddleware<DemoMiddleware>();
    }
}
```

## Demo Middleware

```csharp
public class DemoMiddleware
{
    private const int ExpiryTimeInMins = 10;

    private readonly RequestDelegate Next;

    private readonly WebTokenService WebTokenService;

    public DemoMiddleware(RequestDelegate next, WebTokenService webTokenService)
    {
        Next = next;

        WebTokenService = webTokenService;
    }

    public async Task Invoke(HttpContext ctx)
    {
        var data = "Hello World!";

        var token = WebTokenService.Encrypt(data);

        await WL(ctx, $"Data before: {data}");

        await WL(ctx, $"Web Token: http://example.com?safetoken={token}");

        var decrypted = WebTokenService.Decrypt(token);

        var valid = decrypted.IsValid(ExpiryTimeInMins);

        await WL(ctx, $"IsValid: {valid}");

        await WL(ctx, $"Data after: {decrypted.Data}");

        async Task WL(HttpContext context, string line)
        {
            await context.Response.WriteAsync(line + Environment.NewLine + Environment.NewLine);
        }
    }
}
```


## Output
```
Data before: Hello World!

Web Token: http://example.com?safetoken=5tw1KokuNrAuPgE_pE9RriSYl5EorwfIcQfJ1dL_Dz4hpw.yC6OgYiyfGAiVHdRe

IsValid: True

Data after: Hello World!
```
