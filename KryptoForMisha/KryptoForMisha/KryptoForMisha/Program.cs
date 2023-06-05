using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.ComponentModel.Design;
using System.Text;

namespace KryptoForMisha
{
    public class Program
    {
        public static void Main(string[] args)
        {
            while (true)
            {
                Sign("", "1231231231123123", "4561231231123123");
                Console.WriteLine("Enter data string");
                Console.ReadLine();
            }    
        }

        private static RsaKeyParameters MakeKey(String modulusHexString, String exponentHexString, bool isPrivateKey)
        {
            var modulus = new Org.BouncyCastle.Math.BigInteger(modulusHexString, 16);
            var exponent = new Org.BouncyCastle.Math.BigInteger(exponentHexString, 16);

            return new RsaKeyParameters(isPrivateKey, modulus, exponent);
        }

        public class TestClass : ICipherParameters
        { 
        
        }

        public static String Sign(String data, String privateModulusHexString, String privateExponentHexString)
        {
            /* Make the key */
            //RsaKeyParameters key = MakeKey(privateModulusHexString, privateExponentHexString, true);

            /* Init alg */
            ISigner sig = SignerUtilities.GetSigner("GOST3411WITHECGOST3410-2012-256");

            var key = new TestClass();

            /* Populate key */
            sig.Init(true,key);

            /* Get the bytes to be signed from the string */
            var bytes = Encoding.UTF8.GetBytes(data);

            /* Calc the signature */
            sig.BlockUpdate(bytes, 0, bytes.Length);
            byte[] signature = sig.GenerateSignature();

            /* Base 64 encode the sig so its 8-bit clean */
            var signedString = Convert.ToBase64String(signature);

            return signedString;
        }
    }
}