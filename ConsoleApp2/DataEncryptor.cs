using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp2
{
    public class DataEncryptor
    {
        //A class for encrypting data according to the server encryption model

        private static readonly UTF8Encoding ByteConverter = new();

        //A method for encrypting data according to the server encryption model
        public static string GetStringRSAEncrypt(string str, int size, RSAParameters RSAKeyInfo)
        {
            try
            {
                //Converting an input string to an array of bytes for encryption
                byte[] array = ByteConverter.GetBytes(str);

                //Variable storing the result splitting the input string into arrays "size" 
                byte[][] contentByte = DividingArray(array, size);

                //Variable for coupling encrypted arrays "contentByte"
                byte[] encryptedСontent = Array.Empty<byte>();

                using (RSACryptoServiceProvider RSA = new())
                {
                    RSA.ImportParameters(RSAKeyInfo);
                    //Encrypting arrays from "contentByte" and combining into an array "encryptedContent"
                    for (int i = 0; i < contentByte.Length; i++)
                    {
                        encryptedСontent = encryptedСontent.Concat(RSA.Encrypt(contentByte[i], false)).ToArray();
                    }
                }
                string result = Convert.ToBase64String(encryptedСontent);
                return result;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error GetStringRSAEncrypt:\n{e.Message}\n\n");
                Console.ReadKey();
                Environment.Exit(1);
                return null;
            }
        }

        //Data decryption method according to the server encryption model
        public static string GetStringRSADecrypt(string str, int size, RSAParameters RSAKeyInfo)
        {
            try
            {
                //Converting an input string into an array of bytes for decryption
                byte[] array = Convert.FromBase64String(str);

                //Array for splitting the encryption string into arrays
                byte[][] contentByte = DividingArray(array, size);

                //Variable for connecting decrypted arrays "contentByte"
                byte[] encryptedContent = Array.Empty<byte>();

                using (RSACryptoServiceProvider RSA = new())
                {
                    RSA.ImportParameters(RSAKeyInfo);
                    //Decrypting arrays from "contentByte" and combining into an array "encryptedContent"
                    for (int i = 0; i < contentByte.Length; i++)
                    {
                        encryptedContent = encryptedContent.Concat(RSA.Decrypt(contentByte[i], false)).ToArray();
                    }
                }
                string result = ByteConverter.GetString(encryptedContent);
                return result;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error GetStringRSADecrypt:\n{e.Message}\n\n");
                Console.ReadKey();
                Environment.Exit(1);
                return null;
            }
        }

        //Method for splitting an input byte array into an array of arrays
        private static byte[][] DividingArray(byte[] array, int size)
        {
            //The number of rows is required to split the input array into an array of size (rsa.Key size / 8) - 32
            int NumberArrayRows = (int)Math.Ceiling((double)array.Length / size);

            //Counter for selecting an element from the input array and transferring it to the resulting one
            int k = 0;

            byte[][] buffer = new byte[NumberArrayRows][];

            //In the loop control, a subtraction from "NumberArrayRows" was performed for subsequent processing of the last line outside the loop
            for (int i = 0; i < NumberArrayRows - 1 && NumberArrayRows - 1 != 0; i++)
            {
                buffer[i] = new byte[size];
            }

            //Creating the last row of the resulting array
            if (array.Length % size != 0)
            {
                buffer[NumberArrayRows - 1] = new byte[array.Length % size];
            }
            else
            {
                buffer[NumberArrayRows - 1] = new byte[size];
            }

            //Transferring data from an input array to an output array
            for (var i = 0; i < NumberArrayRows; i++)
            {
                for (var j = 0; j < buffer[i].Length && k < array.Length; j++)
                {
                    buffer[i][j] = array[k];
                    k++;
                }
            }
            return buffer;
        }
    }
}

