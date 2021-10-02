using System;

namespace signing_cs{
    class GenerateUUID {
        public static string generate() {
            Guid guid = Guid.NewGuid();
            return guid.ToString();
        }
    }
}