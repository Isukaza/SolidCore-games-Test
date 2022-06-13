using System;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Linq;
using System.Text.Json;
using System.Net;
using System.Text.RegularExpressions;
using System.IO;

namespace ConsoleApp2
{
    class Program
    {
        // HttpClient is intended to be instantiated once per application, rather than per-use. See Remarks.
        private static readonly HttpClient client = new();
        private static readonly JsonSerializerOptions options = new() { WriteIndented = true };

        public static readonly DataСonnectionServer dataСonnect = GetSetting();

        static async Task Main()
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
                //Checking the availability of configuration data in case of absence termination of the program
                if (dataСonnect is null) Environment.Exit(1);

                //Creating "RSACryptoServiceProvider" objects for server and client
                //the key size is loaded from "DataConnect.SizeKeyRsa(Servr/Client)
                RSACryptoServiceProvider rsaServer = new(dataСonnect.SizeKeyRsaServer), rsaClient = new(dataСonnect.SizeKeyRsaClient);

                string responseData, clientSession;

                AuthenticationData authData = new();

                //Checking the correctness of the authorization data entry
                while (true)
                {
                    Console.Write("Enter login: ");
                    authData.Login = Console.ReadLine().Trim();

                    Console.Write("Enter password: ");
                    authData.Password = Console.ReadLine().Trim();

                    if (!String.IsNullOrEmpty(authData.Login) && !String.IsNullOrEmpty(authData.Password))
                    {
                        Console.WriteLine();
                        break;
                    }
                    Console.WriteLine($"\nIncorrect data, repeat the input\n");
                }

                //Requesting the server's public key
                responseData = await SendRequestAsync(dataСonnect.UriGetPublicKey, "", "", HttpMethod.Get);

                //Entering the public key in "rsaServer"
                rsaServer.FromXmlString(responseData);

                //Getting a session
                clientSession = await Session.GetAsync(authData.Login, authData.Password, rsaClient.ToXmlString(false), options, rsaServer, rsaClient);
                authData = null;
                if (clientSession is null) throw new ArgumentNullException(nameof(clientSession));

                //Requesting a list of files from the server
                responseData = await SendRequestAsync(dataСonnect.UriGetFiles, "", clientSession, HttpMethod.Get);
                responseData = DataEncryptor.GetStringRSADecrypt(responseData, rsaClient.KeySize / 8, rsaClient.ExportParameters(true));
                Console.WriteLine($"Get Files: {responseData}\n\n");

                //Logout with server 
                _ = await SendRequestAsync(dataСonnect.UriLogout, "", clientSession, HttpMethod.Get);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error Main:\n{e.Message}\n\n");
                Console.ReadKey();
                Environment.Exit(1);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine($"\nError Main:\n{e.Message}\n\n");
                Console.ReadKey();
                Environment.Exit(1);
            }
        }

        private static DataСonnectionServer GetSetting()
        {
            try
            {
                StreamReader streamReader = new("DataServer.json");
                DataСonnectionServer data = JsonSerializer.Deserialize<DataСonnectionServer>(streamReader.ReadToEnd());
                return data;
            }
            catch (IOException e)
            {
                Console.WriteLine($"Error GetSetting:\n{e.Message}\n\n");
                Console.ReadKey();
                return null;
            }
            catch (JsonException e)
            {
                Console.WriteLine($"Error GetSetting json:\n{e.Message}\n\n");
                Console.ReadKey();
                return null;
            }
        }

        public static async Task<string> SendRequestAsync(string Uri, string content, string session, HttpMethod httpMethod)
        {
            try
            {
                Console.WriteLine($"URI: {Uri}");
                string responseData = null;
                HttpRequestMessage request;
                HttpResponseMessage response;
                HttpContent responseContent;

                //Building a request to the server
                request = new()
                {
                    RequestUri = new(Uri),
                    Method = httpMethod,
                    Content = new StringContent(content, Encoding.UTF8, "text/plain")
                };
                request.Headers.TryAddWithoutValidation("Authorization", session);

                //Sending a request to the server
                response = await client.SendAsync(request);

                //Getting a response from the server
                Console.WriteLine($"Status code: {response.StatusCode} {((int)response.StatusCode)}\n\n");

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    responseContent = response.Content;
                    responseData = await responseContent.ReadAsStringAsync();
                    Console.WriteLine($"Response data:\n{responseData}\n\n");
                }
                return responseData;
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"\nError SendRequestAsync: \n{e.Message}\n\n");
                return null;
            }
        }
    }
}