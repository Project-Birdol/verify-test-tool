using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace BirdolCrypt
{
    public enum KeyType
    {
        RSA1024,
        RSA2048,
        RSA4096,
        ECDSA,
        None
    }

    class CryptoProvider
    {
        private KeyType keyType;
        private (EllipticCurve.PrivateKey, EllipticCurve.PublicKey) ecdsa;
        private RSACryptoServiceProvider rsa;

        private string privKeyStr;
        private string pubKeyStr;
        private string _uuid;

        public CryptoProvider(KeyType type)
        {
            this.keyType = type;
            this._uuid = Guid.NewGuid().ToString();
            initCrypto();
        }

        public CryptoProvider(KeyType type, string keyFile) : this(type, keyFile, false)
        {
        }

        public CryptoProvider(KeyType type, string keyFile, bool isPubKey)
        {
            this.keyType = type;
            this._uuid = Guid.NewGuid().ToString();
            byte[] keyBytes = File.ReadAllBytes(keyFile);

            if (isPubKey)
            {
                setPubKey(keyBytes); 
            }
            else
            {
                setPrivKey(keyBytes);
            }
        }

        public string CryptoUuid()
        {
            if (string.IsNullOrEmpty(this._uuid))
            {
                this._uuid = Guid.NewGuid().ToString();
            }
            return this._uuid;
        }

        public void ExportPrivKeyFile(string filename)
        {
            switch (this.keyType)
            {
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    string rsaPrivKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)));
                    File.WriteAllText(filename + ".priv", rsaPrivKey);
                    break;
                case KeyType.ECDSA:
                    byte[] dsaPrivKey = ecdsa.Item1.toDer();
                    File.WriteAllBytes(filename + ".priv", dsaPrivKey);
                    break;
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    break; // For code flow error
            }
        }

        public void ExportPubKeyFile(string filename)
        {
            switch (this.keyType)
            {
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    string rsaPubKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    File.WriteAllText(filename + ".pub", rsaPubKey);
                    break;
                case KeyType.ECDSA:
                    byte[] dsaPubKey = ecdsa.Item2.toDer();
                    File.WriteAllBytes(filename + ".pub", dsaPubKey);
                    break;
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    break; // For code flow error
            }
        }

        public string PrivKey
        {
            set
            {
                switch (this.keyType)
                {
                    case KeyType.RSA1024:
                    case KeyType.RSA2048:
                    case KeyType.RSA4096:
                        setPrivKey(value);
                        break;
                    case KeyType.ECDSA:
                        byte[] keyBytes = hexStringToBytes(value);
                        setPrivKey(keyBytes);
                        break;
                    default:
                        Console.Error.WriteLine("Invalid KeyType");
                        Environment.Exit(1);
                        break; // For code flow error
                }
            }

            get
            {
                return privKeyStr;
            }
        }

        public string PubKey
        {
            get
            {
                return pubKeyStr;
            }
        }

        public string KeyTypeName(KeyType type)
        {
            switch (type)
            {
                case KeyType.RSA1024:
                    return "rsa-1024";   
                case KeyType.RSA2048:
                    return "rsa-2048";   
                case KeyType.RSA4096:
                    return "rsa-4096";   
                case KeyType.ECDSA:
                    return "ecdsa";
                default:
                    return "None";
            }
        }

        public byte[] Sign(string msg)
        {
            switch (this.keyType)
            {
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    byte[] rsaSig = rsa.SignData(Encoding.UTF8.GetBytes(msg), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    return rsaSig;
                case KeyType.ECDSA:
                    EllipticCurve.Signature dsaSig = EllipticCurve.Ecdsa.sign(msg, this.ecdsa.Item1);
                    return dsaSig.toDer();
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    return new byte[0];
            } 
        }

        public bool Verify(string msg, string signature)
        {
            switch (this.keyType)
            {
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    return rsa.VerifyData(Encoding.UTF8.GetBytes(msg), hexStringToBytes(signature), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                case KeyType.ECDSA:
                    EllipticCurve.Signature dsaSig = EllipticCurve.Signature.fromDer(hexStringToBytes(signature));
                    return EllipticCurve.Ecdsa.verify(msg, dsaSig, this.ecdsa.Item2); 
                default:
                    Console.Error.WriteLine("** Error: invalid keytype");
                    return false;
            }
        }

        private void setPrivKey(string privKey)
        {
            switch (this.keyType)
            {
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(privKey)));
                    this.privKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)));
                    this.pubKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    break;
                case KeyType.ECDSA:
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    break; // For code flow error
            }
        }

        private void setPrivKey(byte[] privKey)
        {
            switch (this.keyType)
            {
                case KeyType.ECDSA:
                    EllipticCurve.PrivateKey dsaPrivkey = EllipticCurve.PrivateKey.fromDer(privKey);
                    this.ecdsa = (dsaPrivkey, dsaPrivkey.publicKey());
                    this.privKeyStr = Convert.ToHexString(ecdsa.Item1.toDer()); 
                    this.pubKeyStr = Convert.ToHexString(ecdsa.Item2.toDer());
                    break;
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    rsa = new RSACryptoServiceProvider();
                    string keyStr = Encoding.UTF8.GetString(privKey);
                    rsa.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(keyStr)));
                    this.privKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)));
                    this.pubKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    break;
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    break; // For code flow error
            }
        }

        private void setPubKey(byte[] pubKey)
        {
            switch (this.keyType)
            {
                case KeyType.ECDSA:
                    EllipticCurve.PublicKey dsaPubkey = EllipticCurve.PublicKey.fromDer(pubKey);
                    this.ecdsa = (null, dsaPubkey);
                    this.pubKeyStr = Convert.ToHexString(ecdsa.Item2.toDer());
                    break;
                case KeyType.RSA1024:
                case KeyType.RSA2048:
                case KeyType.RSA4096:
                    rsa = new RSACryptoServiceProvider();
                    string keyStr = Encoding.UTF8.GetString(pubKey);
                    rsa.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(keyStr)));
                    this.pubKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    break;
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    break; // For code flow error
                
            }
        }

        private void initCrypto() 
        {
            switch (this.keyType)
            {
                case KeyType.RSA1024:
                    this.rsa = new RSACryptoServiceProvider(1024);
                    this.privKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)));
                    this.pubKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    break;
                case KeyType.RSA2048:
                    this.rsa = new RSACryptoServiceProvider(2048);
                    this.privKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)));
                    this.pubKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    break;
                case KeyType.RSA4096:
                    this.rsa = new RSACryptoServiceProvider(4096);
                    this.privKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)));
                    this.pubKeyStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
                    break;
                case KeyType.ECDSA:
                    var privKey = new EllipticCurve.PrivateKey("secp256k1");
                    this.ecdsa = (privKey, privKey.publicKey());
                    this.privKeyStr = Convert.ToHexString(ecdsa.Item1.toDer()); 
                    this.pubKeyStr = Convert.ToHexString(ecdsa.Item2.toDer());
                    break;
                case KeyType.None:
                    break;
                default:
                    Console.Error.WriteLine("Invalid KeyType");
                    Environment.Exit(1);
                    break; // For code flow error
            }
        }

        private static IEnumerable<string> strSplit(string text, int size)
        {
            if (String.IsNullOrEmpty(text) || size < 1) 
            {
                throw new ArgumentException();
            }

            for(var i = 0; i < text.Length; i += size)
            {
                yield return text.Substring(i, Math.Min(size, text.Length - i));
            }
        }

        private static byte[] hexStringToBytes(string str)
        {
            IEnumerable<string> splited = strSplit(str, 2);
            byte[] bytes = new byte[splited.Count()];
            foreach (var elem in splited.Select((value, index) => new { value, index }))
            {
                bytes[elem.index] = Convert.ToByte(elem.value, 16);
            }
            return bytes;
        }
    }
}
