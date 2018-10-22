using static System.Console;
using CryptographyLib;
using System.Threading;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.Security.Claims;

namespace EncryptionApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //-----------------------------------------------------------------------------------

            //Write("Enter a message that you want to encrypt: ");
            //string message = "xxxxxx"; //ReadLine();
            //Write("Enter a password: ");
            //string password = ReadLine();
            //string cryptoText = Protector.Encrypt(message, password);
            //WriteLine($"Encrypted text: {cryptoText}");
            //Write("Enter the password: ");
            //string password2 = ReadLine();
            //try
            //{
            //    string clearText = Protector.Decrypt(cryptoText, password2);
            //    WriteLine($"Decrypted text: {clearText}");
            //}
            //catch
            //{
            //    WriteLine(
            //        "Enable to decrypt because you entered the wrong password!");
            //}
            //-----------------------------------------------------------------------------------

            //WriteLine("A user named Alice has been registered with Pa$$w0rd as herpassword.");
            //var alice = Protector.Register("Alice", "Pa$$w0rd");
            //WriteLine($"Name: {alice.Name}");
            //WriteLine($"Salt: {alice.Salt}");
            //WriteLine($"Salted and hashed password: {alice.SaltedHashedPassword}");
            //WriteLine();
            //Write("Enter a different username to register: ");
            //string username = ReadLine();
            //Write("Enter a password to register: ");
            //string password = ReadLine();
            //var user = Protector.Register(username, password);
            //WriteLine($"Name: {user.Name}");
            //WriteLine($"Salt: {user.Salt}");
            //WriteLine($"Salted and hashed password: {user.SaltedHashedPassword}");
            //bool correctPassword = false;
            //while (!correctPassword)
            //{
            //    Write("Enter a username to log in: ");
            //    string loginUsername = ReadLine();
            //    Write("Enter a password to log in: ");
            //    string loginPassword = ReadLine();
            //    correctPassword = Protector.CheckPassword(loginUsername,
            //        loginPassword);
            //    if (correctPassword)
            //    {
            //        WriteLine($"Correct! {loginUsername} has been logged in.");
            //    }
            //    else
            //    {
            //        WriteLine("Invalid username or password. Try again.");
            //    }
            //}

            //-----------------------------------------------------------------------------------

            Protector.RegisterSomeUsers();

            Write($"Enter your user name: ");
            string username = ReadLine();
            Write($"Enter your password: ");
            string password = ReadLine();
            Protector.LogIn(username, password);
            if (Thread.CurrentPrincipal == null)
            {
                WriteLine("Log in failed.");
                return;
            }
            var p = Thread.CurrentPrincipal;
            WriteLine($"IsAuthenticated: {p.Identity.IsAuthenticated}");
            WriteLine($"AuthenticationType: {p.Identity.AuthenticationType}");
            WriteLine($"Name: {p.Identity.Name}");
            WriteLine($"IsInRole(\"Admins\"): {p.IsInRole("Admins")}");
            WriteLine($"IsInRole(\"Sales\"): {p.IsInRole("Sales")}");
            if (p is ClaimsPrincipal)
            {
                WriteLine($"{p.Identity.Name} has the following claims:");
                foreach (Claim claim in (p as ClaimsPrincipal).Claims)
                {
                    WriteLine($" {claim.Type}: {claim.Value}");
                }
            }
            ReadKey();
        }
    }
}
