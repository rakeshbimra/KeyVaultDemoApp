using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultDemoApp
{
    public static class KeyVaultCache
    {
        private static Dictionary<string, string> _secretsCache = new Dictionary<string, string>();
        private static KeyVaultClient _keyVaultClient = null;

        public static KeyVaultClient KeyVaultClientInstance
        {
            get
            {
                if (_keyVaultClient == null)
                {
                    _keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetTokenWithCertificateAsync));
                }
                return _keyVaultClient;
            }
        }

        public async static Task<string> GetSecretAsync(string secretName)
        {
            if (!_secretsCache.ContainsKey(secretName))
            {
                string baseUrl = ConfigurationManager.AppSettings["KeyVaultSettingsUrl"];

                var secretBundle = await KeyVaultClientInstance.GetSecretAsync($"{baseUrl}/secrets/{secretName}");

                _secretsCache.Add(secretName, secretBundle.Value);
            }
            return _secretsCache.ContainsKey(secretName) ? _secretsCache[secretName] : string.Empty;
        }

        /// <summary>
        /// Get key vault token with client secret
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static async Task<string> GetTokenWithClientSecretAsync(string authority, string resource, string scope)
        {
            string clientSecret = ConfigurationManager.AppSettings["KeyVaultClientSecret"];

            string clientId = ConfigurationManager.AppSettings["KeyVaultClientSecret"];

            var authContext = new AuthenticationContext(authority);

            ClientCredential clientCredential = new ClientCredential(clientId, clientSecret);

            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCredential);

            if (result == null)
                throw new ArgumentNullException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        /// <summary>
        /// Get key vault token with certificate
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static async Task<string> GetTokenWithCertificateAsync(string authority, string resource, string scope)
        {
            var certificate = GetCertificate(thumbprint: ConfigurationManager.AppSettings["CertificateThumbprint"]);

            var clientAssertionCertificate = new ClientAssertionCertificate(
                clientId: ConfigurationManager.AppSettings["KeyVaultClientId"],
                certificate: certificate);

            var authenticationContext = new AuthenticationContext(authority);

            var result = await authenticationContext.AcquireTokenAsync(resource, clientAssertionCertificate);

            if (result == null)
                throw new ArgumentNullException($"Failed to obtain the JWT token");

            return result.AccessToken;
        }

        private static X509Certificate2 GetCertificate(string thumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            store.Open(OpenFlags.ReadOnly);

            var cert = store.Certificates.OfType<X509Certificate2>()
                .FirstOrDefault(x => x.Thumbprint == thumbprint);

            if (cert == null)
                throw new ArgumentNullException($"Failed to find the certificate for thumbprint:{thumbprint}");

            return cert;
        }
    }
}
