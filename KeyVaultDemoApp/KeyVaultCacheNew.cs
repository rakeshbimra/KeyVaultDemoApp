using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultDemoApp
{
    public class KeyVaultCacheNew
    {
        private const string KeyVaultSettingsUrl = "KeyVaultSettingsUrl";
        private static Dictionary<string, string> _secretCache = new Dictionary<string, string>();
        private static KeyVaultClient _keyVaultClient = null;

        public static KeyVaultClient KeyVaultClient
        {
            get
            {
                if (_keyVaultClient == null)
                {
                    var provider = new AzureServiceTokenProvider();
                    _keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(provider.KeyVaultTokenCallback));
                }
                return _keyVaultClient;
            }
        }

        public async static Task<string> GetSecretAsync(string secretName)
        {
            if (!_secretCache.ContainsKey(secretName))
            {
                string baseUri = GetBaseUri();

                var secretBundle = await _keyVaultClient.GetSecretAsync($"{baseUri}/secrets/{secretName}");

                if (!_secretCache.ContainsKey(secretName))
                    _secretCache.Add(secretName, secretBundle.Value);
            }
            return _secretCache.ContainsKey(secretName) ? _secretCache[secretName] : string.Empty;
        }

        private static string GetBaseUri()
        {
            string baseUri = ConfigurationManager.AppSettings[KeyVaultSettingsUrl];
            return baseUri;
        }
    }
}
