using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.ComponentModel.Design;
using System.Text;
using System.Net.WebSockets;

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

            var a = new Org.BouncyCastle.Math.BigInteger("1234567890123456", 16);
            var b = new Org.BouncyCastle.Math.BigInteger("1234567890123456", 16);
            var c = new Org.BouncyCastle.Math.BigInteger("1234567890123456", 16);

            var ccc = new Gost3410Parameters(a,b,c);

            var x = new Org.BouncyCastle.Math.BigInteger("11", 2);
            var kek = new Gost3410PrivateKeyParameters(x, ccc);

            /* Init alg */
            ISigner sig = SignerUtilities.GetSigner("GOST3411WITHECGOST3410-2012-256");
            
            //var key = new TestClass();

            //const string keyPath = "C:\\Users\\polka\\Documents\\Newfolder\\zalupa.txt";

            //using (var textReader = File.OpenText(keyPath))
            //{
            //    var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(textReader);
            //    var pemObj = pemReader.ReadPemObject();
            //    var seq = (Asn1Sequence)Asn1Object.FromByteArray(pemObj.Content);
            //    var keyInfo = PrivateKeyInfo.GetInstance(seq);
            //    var akp = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(keyInfo);
            //}

            /* Populate key */
            //sig.Init(true,key);
            sig.Init(true, kek);

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