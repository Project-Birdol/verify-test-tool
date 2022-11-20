using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace signing_cs
{
    class RSASigning
    {
        public static void Signing(string input, string keyfile)
        {
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            string privatekey = File.ReadAllText(keyfile);
            csp.FromXmlString(privatekey);
            byte[] signature = csp.SignData(Encoding.UTF8.GetBytes(input), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            Console.WriteLine(BitConverter.ToString(signature).Replace("-", "").ToLower());
        }
    }
}
