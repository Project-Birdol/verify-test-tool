using System;

namespace BirdolCrypt
{
    class Program
    {
        static int Main(string[] args)
        {
            int argc = args.Length;
            if (argc < 1)
            {
                Console.Error.WriteLine("** Error: insufficient arguments");
                return 1;
            }
            string cmd = args[0];
            switch(cmd) {
                case "keygen":
                    if (argc < 3)
                    {
                        Console.Error.WriteLine("** Error: insufficient arguments");
                        return 1;
                    }
                    {
                        string name = args[1];
                        string keyType = args[2];
                        switch (keyType)
                        {
                            case "rsa-1024":
                                CryptoProvider CryptoRsa1024 = new CryptoProvider(KeyType.RSA1024);
                                CryptoRsa1024.ExportPrivKeyFile(name);
                                Console.Write(CryptoRsa1024.PubKey);
                                break;
                            case "rsa-2048":
                                CryptoProvider CryptoRsa2048 = new CryptoProvider(KeyType.RSA2048);
                                CryptoRsa2048.ExportPrivKeyFile(name);
                                Console.Write(CryptoRsa2048.PubKey);
                                break;
                            case "rsa-4096":
                                CryptoProvider CryptoRsa4096 = new CryptoProvider(KeyType.RSA4096);
                                CryptoRsa4096.ExportPrivKeyFile(name);
                                Console.Write(CryptoRsa4096.PubKey);
                                break;
                            case "ecdsa":
                                CryptoProvider CryptoEcdsa = new CryptoProvider(KeyType.ECDSA);
                                CryptoEcdsa.ExportPrivKeyFile(name);
                                Console.Write(CryptoEcdsa.PubKey);
                                break;
                            default:
                                Console.Error.WriteLine("** Error: invalid keytype specified");
                                Console.Error.WriteLine("Available keytype: rsa-1024, rsa-2048, rsa-4096, ecdsa");
                                return 1;
                        }
                    }
                    break;

                case "makepub":
                    if (argc < 3)
                    {
                        Console.Error.WriteLine("** Error: insufficient arguments");
                        return 1;
                    }
                    {
                        string keyType = args[1];
                        string privKeyFile = args[2];
                        switch (keyType)
                        {
                            case "rsa-1024":
                                CryptoProvider CryptoRsa1024 = new CryptoProvider(KeyType.RSA1024, privKeyFile);
                                CryptoRsa1024.ExportPubKeyFile(privKeyFile.Replace(".priv", ""));
                                break;
                            case "rsa-2048":
                                CryptoProvider CryptoRsa2048 = new CryptoProvider(KeyType.RSA2048, privKeyFile);
                                CryptoRsa2048.ExportPubKeyFile(privKeyFile.Replace(".priv", ""));
                                break;
                            case "rsa-4096":
                                CryptoProvider CryptoRsa4096 = new CryptoProvider(KeyType.RSA4096, privKeyFile);
                                CryptoRsa4096.ExportPubKeyFile(privKeyFile.Replace(".priv", ""));
                                break;
                            case "ecdsa": 
                                CryptoProvider CryptoEcdsa = new CryptoProvider(KeyType.ECDSA, privKeyFile);
                                CryptoEcdsa.ExportPubKeyFile(privKeyFile.Replace(".priv", ""));
                                break;
                            default:
                                Console.Error.WriteLine("** Error: invalid keytype specified");
                                Console.Error.WriteLine("Available keytype: rsa-1024, rsa-2048, rsa-4096, ecdsa");
                                return 1;
                        }
                    }
                    break;

                case "sign":
                    if (argc < 4)
                    {
                        Console.Error.WriteLine("** Error: insufficient arguments");
                        return 1;
                    }
                    {
                        string input = args[1];
                        string keyType = args[2];
                        string keyfile = args[3];
                        switch (keyType)
                        {
                            case "rsa-1024":
                                CryptoProvider CryptoRsa1024 = new CryptoProvider(KeyType.RSA1024, keyfile);
                                Console.Write(Convert.ToHexString(CryptoRsa1024.Sign(input)));
                                break;
                            case "rsa-2048":
                                CryptoProvider CryptoRsa2048 = new CryptoProvider(KeyType.RSA2048, keyfile);
                                Console.Write(Convert.ToHexString(CryptoRsa2048.Sign(input)));
                                break;
                            case "rsa-4096":
                                CryptoProvider CryptoRsa4096 = new CryptoProvider(KeyType.RSA4096, keyfile);
                                Console.Write(Convert.ToHexString(CryptoRsa4096.Sign(input)));
                                break;
                            case "ecdsa":
                                CryptoProvider CryptoEcdsa = new CryptoProvider(KeyType.ECDSA, keyfile);
                                Console.Write(Convert.ToHexString(CryptoEcdsa.Sign(input)));
                                break;
                            default:
                                Console.Error.WriteLine("** Error: invalid keytype specified");
                                Console.Error.WriteLine("Available keytype: rsa-1024, rsa-2048, rsa-4096, ecdsa");
                                return 1;
                        }
                    }
                    break;

                case "verify":
                    if (argc < 5)
                    {
                        Console.Error.WriteLine("** Error: insufficient arguments");
                        return 1;
                    }
                    {
                        string msg = args[1];
                        string signature = args[2];
                        string keyType = args[3];
                        string pubKeyFile = args[4];
                        CryptoProvider Crypto;
                        switch (keyType)
                        {
                            case "rsa-1024":
                                Crypto = new CryptoProvider(KeyType.RSA1024, pubKeyFile, true);
                                break;
                            case "rsa-2048":
                                Crypto = new CryptoProvider(KeyType.RSA2048, pubKeyFile, true);
                                break;
                            case "rsa-4096":
                                Crypto = new CryptoProvider(KeyType.RSA2048, pubKeyFile, true);
                                break;
                            case "ecdsa": 
                                Crypto = new CryptoProvider(KeyType.ECDSA, pubKeyFile, true);
                                break;
                            default:
                                Console.Error.WriteLine("** Error: invalid keytype specified");
                                Console.Error.WriteLine("Available keytype: rsa-1024, rsa-2048, rsa-4096, ecdsa");
                                return 1;
                        }
                        if (Crypto.Verify(msg, signature))
                        {
                            Console.WriteLine("This signature is valid!");
                            return 0;
                        }
                        else
                        {
                            Console.WriteLine("This signature is invalid!");
                            return 0;
                        }
                    }

                case "uuid":
                    CryptoProvider uuid = new CryptoProvider(KeyType.None);
                    Console.WriteLine(uuid.CryptoUuid());
                    break;

                default:
                    Console.Error.WriteLine("**Error: invalid command");
                    Console.Error.WriteLine("Available commands: keygen, makepub, sign, verify, uuid");
                    return 1;
            }
            return 0;
        }
    }
}
