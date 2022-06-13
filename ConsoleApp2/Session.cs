using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace ConsoleApp2
{
    public static class Session
    {
        //A class for implementing a method for getting a session
        public static async Task<string> GetAsync(string login, string password, string rsaClientPublicKey, JsonSerializerOptions options, RSACryptoServiceProvider rsaServer, RSACryptoServiceProvider rsaClient)
        {
            try
            {
                string session, jsonStr, requestСontent, responseData;

                //Formation of the authorization object
                LoginDTO loginObj = new()
                {
                    PublicKey = rsaClientPublicKey,
                    Login = login,
                    Password = password,
                    Language = "en",
                    Product = new()
                    {
                        { "name", "Express" },
                        { "version", "1.0.0.0" }
                    }
                };

                jsonStr = JsonSerializer.Serialize<LoginDTO>(loginObj, options);

                requestСontent = DataEncryptor.GetStringRSAEncrypt(jsonStr, (rsaServer.KeySize / 8) - 32, rsaServer.ExportParameters(false));

                responseData = await Program.SendRequestAsync(Program.dataСonnect.UriLogin, requestСontent, "", HttpMethod.Post);
                if (responseData is null) throw new ArgumentNullException(nameof(responseData));

                responseData = DataEncryptor.GetStringRSADecrypt(responseData, rsaClient.KeySize / 8, rsaClient.ExportParameters(true));
                Console.WriteLine($"Respone data:\n{responseData}\n\n");

                session = DataEncryptor.GetStringRSAEncrypt(responseData, (rsaServer.KeySize / 8) - 32, rsaServer.ExportParameters(false));
                Console.WriteLine($"Session:\n{session}\n\n");

                return session;
            }
            catch (NotSupportedException e)
            {
                Console.WriteLine($"Error Session.GetAsync:\n{e.Message}\n\n");
                return null;
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine($"\nError Session.GetAsync:\n{e.Message}\n\n");
                return null;
            }
        }
    }
}
