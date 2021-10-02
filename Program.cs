using System;

namespace signing_cs
{
    class Program
    {
        static void Main(string[] args)
        {
            string type = args[0];
            switch(type) {
                case "gen":
                    string name = args[1];
                    Encrypt.CreateKeyPair(name);
                    break;

                case "sign":
                    string input = args[1];
                    string keyfile = args[2];
                    RSASigning.Signing(input, keyfile);
                    break;

                case "uuid":
                    Console.WriteLine(GenerateUUID.generate());
                    break;

                default:
                    Console.WriteLine("Invalid Argument");
                    Environment.Exit(1);
                    break;
            }
        }
    }
}
