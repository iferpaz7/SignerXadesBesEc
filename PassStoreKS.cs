using es.mityc.javasign.pkstore;
using java.security.cert;

namespace SignerXadesBesEc
{
    internal class PassStoreKS : IPassStoreKS
    {
        private readonly string password;

        public PassStoreKS(string password)
        {
            this.password = password;
        }

        public char[] getPassword(X509Certificate certificate, string alias)
        {
            return password.ToCharArray();
        }
    }
}