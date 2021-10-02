using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace signing_cs
{
    class Encrypt
    {
        public static void CreateKeyPair(string name)
        {
            int size = 1024;
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(size);
            string publicKey = csp.ToXmlString(false);
            string privateKey = csp.ToXmlString(true);
            File.WriteAllText(name + ".xml", privateKey);
            string encoded_public = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKey));
            Console.WriteLine(encoded_public);
        }
    }
}