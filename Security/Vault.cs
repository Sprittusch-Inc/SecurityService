using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

namespace Security;
public class Vault
{
    private readonly IConfiguration _config;
    private readonly string? EndPoint;
    private HttpClientHandler httpClientHandler;

    public Vault(IConfiguration config)
    {
        _config = config;
        EndPoint = _config["Vault_EndPoint"];
        httpClientHandler = new HttpClientHandler();
        httpClientHandler.ServerCertificateCustomValidationCallback =
        (message, cert, chain, sslPolicyErrors) => { return true; };

    }

    //Henter secret fra vault
    public async Task<string> GetSecret(string path, string key)
    {
        //Hvilken auth method der skal bruges samt hvilken token der skal bruges
        IAuthMethodInfo authMethod = new TokenAuthMethodInfo(_config["Vault_Token"]);

        //En Constructor til VaultClientSettings, som er en klasse der indeholder alle settings til VaultClient
        var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
        {
            Namespace = "",
            MyHttpClientProviderFunc = handler
            => new HttpClient(httpClientHandler)
            {
                BaseAddress = new Uri(EndPoint)
            }
        };

        IVaultClient vaultClient = new VaultClient(vaultClientSettings);
        //Bruger klienten til at hente key value secreten
        Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: path, mountPoint: "secret");

        var secret = kv2Secret.Data.Data[key];

        return secret.ToString();
    }
}