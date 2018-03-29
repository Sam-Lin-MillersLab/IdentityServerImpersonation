using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using IdentityModel.Client;

namespace ApiConsoleClient
{
    class Program
    {
        static void Main(string[] args) => MainAsync().GetAwaiter().GetResult();

        static async Task MainAsync()
        {
            var tokenClient = new TokenClient("http://localhost:3308/connect/token",
                "console", "secret");
            var tokenResult = await tokenClient.RequestClientCredentialsAsync("api1");
            if (tokenResult.IsError)
            {
                Console.WriteLine("Token Error: " + tokenResult.Error);
                return;
            }

            Console.WriteLine(tokenResult.Raw);
            Console.WriteLine();


            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", tokenResult.AccessToken);

            var result = await client.GetAsync("http://localhost:3414/test");
            Console.WriteLine($"API Status: {(int)result.StatusCode}");

            if (result.IsSuccessStatusCode)
            {
                var json = await result.Content.ReadAsStringAsync();
                Console.WriteLine(json);
            }
        }
    }
}
