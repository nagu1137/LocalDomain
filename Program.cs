using System;

using System.Collections.Generic;

using System.Linq;

using System.Security.Principal;

using System.Text;

using System.Threading.Tasks;

using System.DirectoryServices;

using System.DirectoryServices.ActiveDirectory;
namespace FindDomainAdmin
{

    internal class Program

    {

        private static SecurityIdentifier result;

        private static SecurityIdentifier GetDomainSid(Domain domain)

        {

            using (DirectoryEntry domainEntry = domain.GetDirectoryEntry())

            {

                var binaryDomainSid = (byte[])domainEntry.Properties["objectSid"].Value;

                var result = new SecurityIdentifier(binaryDomainSid, 0);



                return result;

            }

        }



        public static bool IsUserAdmin()

        {

            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())

            {

                Console.WriteLine($"current Identity:{identity.Name}");

                Console.WriteLine($"current user sid:{identity.User}");





                // Translate AccountDomainAdminsSid to display name

                var resultNTAccount = identity.User.Translate(typeof(NTAccount)) as NTAccount;

                string resultDisplayName = resultNTAccount?.Value ?? "Unable to translate";

                Console.WriteLine($"NT Account: {resultDisplayName}");

                WindowsPrincipal wp = new WindowsPrincipal(identity);

                return wp.IsInRole(result.Value);

            }

        }









        static void Main(string[] args)

        {

            Console.WriteLine("PressKeyToContinue");

            Console.WriteLine("If fully qualified name is - DC.Goku.local, then you need to pass Goku.local");

            Console.ReadKey(true);

            if (args.Length <= 0)

            {

                Console.WriteLine("Invalid Command: try - FindDomainAdmin <DomainName>");

                return;



            }

            Domain domObj = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, args[0]));

            var domainSid = GetDomainSid(domObj);

            Console.WriteLine($"Domain SID: {domainSid.Value}");

            result = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, domainSid);

            Console.WriteLine($"BuiltinAdministratorsSid: {result.Value}");





            if (IsUserAdmin())

            {

                Console.WriteLine(" admin group");

            }

            else

            {

                Console.WriteLine($"Non Admin Group");

            }



        }

    }

}


