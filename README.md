# Web Safe Token Service
Create time sensitive encrypted tokens that are safe to transmit via query string paramteters.

## appsettings.json
Key is a 32 char string
```
{
  "Encryption": {
    "Key": "DO_NOT_USE_THIS_DO_NOT_USE_THIS!" 
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
}
```

## Example

```csharp
public class Example
{
    private const int ExpiryTimeInMins = 10;

    private readonly WebTokenService WebTokenService;

    public Example(WebTokenService webTokenService)
    {
        WebTokenService = webTokenService;
    }

    public void Demo(HttpContext ctx)
    {
        var data = "123456789";

        // Token as a url safe string
        var token = WebTokenService.Encrypt(data);

        var url = $"http://example.com?safetoken={token}";

        // Use the url in emails etc
        // ...
        // ...
 
        var decrypted = WebTokenService.Decrypt(token);

        // Is it valid?
        const int ExpiryTimeInMins = 10;
        var valid = decrypted.IsValid(ExpiryTimeInMins);

        if (valid)
        {
            // Do something with the data...
            var userid = int.Parse(decrypted.Data);
        }
    }
}
```
