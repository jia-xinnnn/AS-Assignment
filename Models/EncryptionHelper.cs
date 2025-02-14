using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.IO;
using Microsoft.AspNetCore.DataProtection;

namespace _233506D.Models
{
    public static class EncryptionHelper
    {
        private static readonly IDataProtector _protector;

        static EncryptionHelper()
        {
            var provider = DataProtectionProvider.Create("EncryptData");
            _protector = provider.CreateProtector("MySecretKey");
        }

        public static string Encrypt(string plainText)
        {
            return _protector.Protect(plainText);
        }

        public static string Decrypt(string encryptedText)
        {
            return _protector.Unprotect(encryptedText);
        }
    }
}
