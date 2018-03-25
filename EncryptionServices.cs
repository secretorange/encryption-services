using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SecretOrange.Core.Encryption;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecretOrange.Core.Encryption
{
    public class EncryptionService
    {
        private EncryptionOptions Options;

        public EncryptionService(IOptions<EncryptionOptions> options)
        {
            Options = options.Value;
        }

        public string Encrypt(string text)
        {
            if (String.IsNullOrWhiteSpace(Options.Key))
                throw new Exception("There is no encryption key");

            var key = Encoding.UTF8.GetBytes(Options.Key);

            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        var iv = aesAlg.IV;

                        var content = msEncrypt.ToArray();

                        var result = new byte[iv.Length + content.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(content, 0, result, iv.Length, content.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        public string Decrypt(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
                return text;

            if (String.IsNullOrWhiteSpace(Options.Key))
                throw new Exception("There is no encryption key");

            var fullCipher = Convert.FromBase64String(text);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);
            var key = Encoding.UTF8.GetBytes(Options.Key);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }
    }

    public class WebTokenService
    {
        private readonly EncryptionService EncryptionService;

        public WebTokenService(EncryptionService encryptionService)
        {
            EncryptionService = encryptionService;
        }

        public WebToken Decrypt(string token)
        {
            var data = EncryptionService.Decrypt(Decode(token));

            var index = data.IndexOf('|');
            var date = new DateTime(long.Parse(data.Substring(0, index)), DateTimeKind.Utc);

            return new WebToken()
            {
                CreateDate = date,
                Data = data.Substring(index + 1)
            };
        }

        public string Encrypt(string data)
        {
            return Encrypt(new WebToken()
            {
                CreateDate = DateTime.UtcNow,
                Data = data
            });
        }

        public string Encrypt(WebToken token)
        {
            var data = $"{token.CreateDate.ToUniversalTime().Ticks.ToString()}|{token.Data}";

            return Encode(EncryptionService.Encrypt(data));
        }

        private string Encode(string base64Input)
        {
            return base64Input.Replace('+', '.').Replace('/', '_').Replace('=', '-');
        }

        private string Decode(string encodedBase64Input)
        {
            return encodedBase64Input.Replace('.', '+').Replace('_', '/').Replace('-', '=');
        }
    }

    public class EncryptionOptions
    {
        // Key should be 32 chars long
        public string Key { get; set; }
    }

    public class WebToken
    {
        public string Data { get; set; }

        public DateTime CreateDate { get; set; }

        public bool IsValid(int expiryTimeInMinutes)
        {
            return CreateDate.AddMinutes(expiryTimeInMinutes) > DateTime.UtcNow;
        }
    }
}

namespace Microsoft.Extensions.DependencyInjection
{
    public static class EncryptionServicesStartupExtensions
    {
        public static void AddEncryptionServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddSingleton<EncryptionService>();
            services.AddSingleton<WebTokenService>();
            
            services.Configure<EncryptionOptions>(configuration.GetSection("Encryption"));
        }
    }
}
