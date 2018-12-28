using System;
using System.Security.Cryptography;
using System.Numerics;

namespace c_sharp_crypto
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Ready...");

            /*   Key generation   */

            // Get two (large) prime numbers 'p' and 'q' (ex.: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
            long p = 7, q = 11; 
            Console.WriteLine($"Two prime numbers chosen: p = {p}, q = {q}");

            // Calculate product of these prime numbers 'n', which is one half of the public key:
            var n = p * q;
            Console.WriteLine($"Product of prime numbers: n = {n}");

            // Calculate ϕ(pq):
            var phi = (p - 1) * (q - 1);
            Console.WriteLine($"phi(pq) = {phi}");

            // Calculate 'e', which is a number relatively prime to ϕ. Two positive integers are relatively prime if their greatest common divisor is 1.
            // Rule: 1 < e < ϕ
            var e = 7;
            Console.WriteLine($"e = {e}");

            // Calculate 'd', which is a modular inverse of 'e' modulo ϕ. 'd' is the private key. 
            // Equation: (d * e) mod ϕ = 1   OR   d = (1 / e) mod ϕ
            // Rule: 1 < d < ϕ
            var d = CalculateD(e, phi);
            Console.WriteLine($"Private key: d = {d}");







            /*   Encryption   */
            Console.WriteLine();
            Console.WriteLine("Starting encryption stage...");

            // Rule: 0 < m < n - 1
            var m = n / 2;
            Console.WriteLine($"Message to be encrypted: '{m}'");
            Console.WriteLine($"Using public key ({e},{n}) to encrypt the message.");

            // Encrypt the message using the public key (e, n)
            // Rquation: c = m^e mod n
            var c = Math.Pow(m, e) % n;
            Console.WriteLine($"Result ciphertext: {c}");







            /*   Decryption   */
            Console.WriteLine();
            Console.WriteLine("Starting decryption stage...");

            // Have to use BigInteger from System.Numerics since Math.Pow works with double, and gives inaccurate results for large numbers.
            // m = c^d mod n.          
            Console.WriteLine($"Using private key ({d},{n}) to decrypt the message.");
            var decryptedMessage = BigInteger.Pow((BigInteger)c, (int)d) % n;
            Console.WriteLine($"Decrypted message: {decryptedMessage.ToString()}");





            //Leave console window open:
            Console.ReadLine();
        }

        static long CalculateD(long e, long phi)
        {
            long a = 0, b = phi, u = 1;

            while (e > 0)
            {
                var q = b / e;
                var newE = b % e;
                var newA = u;
                var newB = e;
                var newU = a - q * u;
                e = newE;
                a = newA;
                b = newB;
                u = newU;
            }

            if (b == 1) return (a % phi + phi) % phi;

            return -1;
        }

        /// <summary>
        /// Source: https://stackoverflow.com/questions/17128038/c-sharp-rsa-encryption-decryption-with-transmission
        /// </summary>
        static void InternetExample()
        {
            //lets take a new CSP with a new 2048 bit rsa key pair
            var csp = new RSACryptoServiceProvider(2048);

            //how to get the private key
            var privKey = csp.ExportParameters(true);

            //and the public key ...
            var pubKey = csp.ExportParameters(false);

            //converting the public key into a string representation
            string pubKeyString;
            {
                //we need some buffer
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, pubKey);
                //get the string from the stream
                pubKeyString = sw.ToString();
            }

            //converting it back
            {
                //get a stream from the string
                var sr = new System.IO.StringReader(pubKeyString);
                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //get the object back from the stream
                pubKey = (RSAParameters)xs.Deserialize(sr);
            }

            //conversion for the private key is no black magic either ... omitted

            //we have a public key ... let's get a new csp and load that key
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(pubKey);

            //we need some data to encrypt
            var plainTextData = "foobar";

            //for encryption, always handle bytes...
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

            //apply pkcs#1.5 padding and encrypt our data 
            var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

            //we might want a string representation of our cypher text... base64 will do
            var cypherText = Convert.ToBase64String(bytesCypherText);


            /*
             * some transmission / storage / retrieval
             * 
             * and we want to decrypt our cypherText
             */

            //first, get our bytes back from the base64 string ...
            bytesCypherText = Convert.FromBase64String(cypherText);

            //we want to decrypt, therefore we need a csp and load our private key
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(privKey);

            //decrypt and strip pkcs#1.5 padding
            bytesPlainTextData = csp.Decrypt(bytesCypherText, false);

            //get our original plainText back...
            plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);
        }
    }
}
