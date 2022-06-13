using System;
using System.Collections.Generic;

namespace ConsoleApp2
{
    //Data Authentication
    public class AuthenticationData
    {
        public string Login { get; set; }
        public string Password { get; set; }
    }
    //A model for storing the server api URI and encryption data
    public class DataСonnectionServer
    {
        public int SizeKeyRsaClient { get; set; }
        public int SizeKeyRsaServer { get; set; }
        public string UriGetPublicKey { get; set; }
        public string UriLogin { get; set; }
        public string UriLogout { get; set; }
        public string UriGetFiles { get; set; }
    }

    //The data packaging model for authorization on the server
    public class LoginDTO
    {
        public string PublicKey { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public string Language { get; set; }
        public Dictionary<string, string> Product { get; set; }
    }
}
