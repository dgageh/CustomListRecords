
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Bond;
using Microsoft.Search.ObjectStore;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.ObjectStore;
using Microsoft.Identity.Client;
using Microsoft.Extensions.CommandLineUtils;
using System.IdentityModel.Metadata;
using CustomList;
using Guid = System.Guid;
using System.Windows.Forms;


namespace CustomListPoc
{
    class Program
    {

        public const string EnvironmentEndpoint = "https://objectstorebingfd.int.westus2.binginternal.com:443/sds";
        //Use https://objectstorebingfd.int.westus2.binginternal.com:443/sds URL when code is downloaded/executed from devbox or internet (not AP backend). See more details here: https://eng.ms/docs/experiences-devices/webxt/search-content-platform/objectstore/objectstore/objectstore-public-wiki/getting-started/pf-environments
        public const string NamespaceName = "DFP-CRE";
        public const string TableName = "CustomListPoc";
        public const StoreName CertificateStoreName = StoreName.My;
        public const StoreLocation CertificateStoreLocation = StoreLocation.CurrentUser;
        public static X509CertificateCollection Certificates = LoadCert();
        public static IClient<Key, Value> client = null;
        public static Dictionary<string, string> header = new Dictionary<string, string>();
        public static string token = string.Empty;
        public static Random random = new Random();
        public static ClientInstrumentation instrumentation = new ClientInstrumentation();
        public static List<(string Operation, long TotalLatency, long ServerSideLatency)> Stats = new List<(string Operation, long TotalLatency, long ServerSideLatency)>();

        public static string[] TenantIds =
        {
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        };

        public static string[] EnvironmentIds =
        {
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        };

        public static string[] ListNames =
        {
            "My First List",
            "My Second List"
        };
        public static string TenantId = TenantIds[0];
        public static string EnvironmentId = EnvironmentIds[0];
        public static string ListName = ListNames[0];


        public static int minWriteSizeKb = 1000;
        public static int maxWriteSizeKb = 10000;

        // Hard-coded config

        public static int chunkSizeKb = 500;

        static void GuidToParts(Guid guid, out ulong part1, out ulong part2)
        {
            var bytes = guid.ToByteArray();
            part1 = 0;
            part2 = 0;
            part1 |= (ulong)BitConverter.ToUInt32(bytes, 0) << 32;
            part1 |= (ulong)BitConverter.ToUInt16(bytes, 4) << 16;
            part1 |= (ulong)BitConverter.ToUInt16(bytes, 6);
            part2 |= (ulong)bytes[8] << 56;
            part2 |= (ulong)bytes[9] << 48;
            part2 |= (ulong)bytes[10] << 40;
            part2 |= (ulong)bytes[11] << 32;
            part2 |= (ulong)bytes[12] << 24;
            part2 |= (ulong)bytes[13] << 16;
            part2 |= (ulong)bytes[14] << 8;
            part2 |= (ulong)bytes[15];
        }

        static Guid GuidFromParts(ulong part1, ulong part2)
        {
            return new Guid((uint)(part1 >> 32), (ushort)(part1 >> 16), (ushort)(part1), (byte)(part2 >> 56), (byte)(part2 >> 48), (byte)(part2 >> 40), (byte)(part2 >> 32), (byte)(part2 >> 24), (byte)(part2 >> 16), (byte)(part2 >> 8), (byte)(part2));
        }

        public static X509CertificateCollection LoadCert()
        {
            X509Store store = new X509Store(CertificateStoreName, CertificateStoreLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                string thumbPrint = "51AF4C69F27A399B59971A16F1677688FDBFF7BE";
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint, false);

                if (certs.Count > 0)
                {
                    Console.WriteLine("Certificate is found. FriendlyName: " + certs[0].FriendlyName);
                    return GetX509CertificateCollection(certs[0]);
                }
            }
            finally
            {
                store.Close();
            }
            return null;
        }

        public static X509CertificateCollection GetX509CertificateCollection(X509Certificate2 cert)
        {
            return cert != null ? new X509CertificateCollection(new[] { cert }) : null;
        }

        static async Task Write(IEnumerable<KeyValuePair<Key, Value>> keyValuePairs)
        {
            await client.Write(keyValuePairs).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
            Stats.Add(("Write", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
        }

        static async Task<List<Value>> Read(IEnumerable<Key> keys)
        {
            var result = new List<Value>();
            if (keys.Any())
            {
                result = await client.Read(keys).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
                Stats.Add(("Read", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
            }

            return result;
        }

        static async Task<List<bool>> ContainsKeys(IEnumerable<Key> keys)
        {
            var result = await client.ContainsKeys(keys).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
            Stats.Add(("ContainsKeys", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
            return result;
        }

        static async Task Delete(IEnumerable<Key> keys)
        {
            await client.Delete(keys).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
            Stats.Add(("Delete", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
        }

  
        static async Task Waiter()
        {
            if (waitfor > 0)
            {
                Console.WriteLine($"Waiting {waitfor} milliseconds");
                await Task.Delay(waitfor);
            }
        }

        internal class MyCommandOptions
        {
            public CommandOption CommandOption { get; set; }
            public string Description { get; set; }
            public int Value { get; set; }
        }
        static Dictionary<string, MyCommandOptions> myCommands = new Dictionary<string, MyCommandOptions>();
        
        static void AddCommandOption(CommandLineApplication app, string command,  string description)
        {
            string cmdLineOption = $"--{command}";
            var option = app.Option(cmdLineOption, description, CommandOptionType.SingleValue);
            myCommands.Add(cmdLineOption, new MyCommandOptions { CommandOption = option, Description = description, Value = 0 });
        }

        static void CommandLine(string[] args)
        {
            var app = new CommandLineApplication();

            // Define options
            app.HelpOption("-? | --help");

            AddCommandOption(app, "import-list", "Specify which list Guid to import");
            AddCommandOption(app, "delete-list","Specify which list to delete");
            AddCommandOption(app, "read-keys","Specify which list to read keys from");
            AddCommandOption(app, "upsert-keys","Specify which list to read keys from");
            AddCommandOption(app, "rows","How many rows");
            AddCommandOption(app, "columns","How many columns");
            AddCommandOption(app, "read-key","Reads the key at row/col from list n");
            AddCommandOption(app, "update-key","Reads and updates the key at row/col from list n\");");
            AddCommandOption(app, "delete-key","Deletes the key at row/col from list n");
            AddCommandOption(app, "row","Operates on the key at the given row. Increments each iteration");
            AddCommandOption(app, "col","Operates on the key at the given col. Increments each iteration");
            AddCommandOption(app, "iterations","Specificy Number of Iterations");
            AddCommandOption(app, "wait","Wait for n miliseconds after each operation");

            app.OnExecute(() =>
            {
                if (app.IsShowingInformation)
                {
                    foreach (var kvp in myCommands)
                    {
                        Console.WriteLine(kvp.Key, kvp.Value.Description);
                    }
                }

                foreach (var kvp in myCommands)
                {
                    if (kvp.Value.CommandOption.HasValue())
                    {
                        int i;
                        if (int.TryParse(kvp.Value.CommandOption.Value(), out i))
                        {
                            kvp.Value.Value = i;
                            Console.WriteLine($"{kvp.Key} is {i}");
                        }
                        else
                        {
                            throw new InvalidDataException();

                        }
                    }
                }
                return 0;
            });

            app.Execute(args);
        }

        public static void PrintStats()
        {
            var groupedStats = Stats
                .GroupBy(t => t.Operation)
                .Select(g => new
                {
                    Operation = g.Key,
                    RecordCount = g.Count(),
                    TotalTotalLatency = g.Sum(t => t.TotalLatency),
                    TotalServerSideLatency = g.Sum(t => t.ServerSideLatency),
                    AverageTotalLatency = g.Average(t => t.TotalLatency),
                    AverageServerSideLatency = g.Average(t => t.ServerSideLatency)
                });

            foreach (var result in groupedStats)
            {
                Console.WriteLine("");
                Console.WriteLine($"Operation: {result.Operation}");
                Console.WriteLine($"Calls: {result.RecordCount}");
                Console.WriteLine($"Total Total Latency: {result.TotalTotalLatency}");
                Console.WriteLine($"Total Server-Side Latency: {result.TotalServerSideLatency}");
                Console.WriteLine($"Average Total Latency: {result.AverageTotalLatency}");
                Console.WriteLine($"Average Server-Side Latency: {result.AverageServerSideLatency}");
                Console.WriteLine();
            }
        }

        static IObjectStoreClientBuilder<Key, Value> BuildClient()
        {
            if (Certificates == null)
            {
                TokenGetter tokenGetter = new TokenGetter();
                Task<string> tokenTask = tokenGetter.GetAADUserToken();
                tokenTask.Wait();
                token = tokenTask.Result;
            }

            string traceId = Guid.NewGuid().ToString("N");
            header.Add("X-TraceId", traceId);
            if (token != null)
            {
                header.Add("Authorization", "Bearer " + token);
            }

            var clientBuilder = Client.Builder<Key, Value>(
                environment: EnvironmentEndpoint,
                osNamespace: NamespaceName,
                osTable: TableName,
                timeout: TimeSpan.FromMilliseconds(2000),
                maxRetries: 0);


            if (Certificates != null)
            {
                clientBuilder.WithClientCertificates(Certificates);
            }
            //clientBuilder.WithClientVersion(ClientVersion.V2);
            return clientBuilder;
        }

        ​   static void LogResults(List<IDataLoadResult> results)
        {
            foreach (IDataLoadResult result in results)
            {
                if (result.IsSuccessful)
                {
                    Console.WriteLine("Record {0}: Writing to all locations successful", result.Context);
                }
                else
                {
                    Console.WriteLine("Record {0}: Writing failed to {1} locations: {2}", result.Context, result.FailedLocations.Count, String.Join(", ", result.FailedLocations));
                }
            }
        }

        private static async Task RecordMode()
        {​       
            List<ITableLocation> locations = new List<ITableLocation>
            {
           // To use https protocol, pass an https URL like https://objectstoremulti.int.co.bing-int.com:443
           // If the full path is not given,  it will add the prefix as “http” instead of https
           new Microsoft.ObjectStore.VIP("ObjectStoreMulti.INT.CO.bing-int.com:83"), // Recommended way, see aka.ms/ObjectStore for list of VIPs​
           new Microsoft.ObjectStore.Environment("ObjectStoreDailyLarge-Int-Co3") // DC names can change, Recommended usage is through environment agnostic VIP like above, see aka.ms/ObjectStore for list of VIPs
           new Microsoft.ObjectStore.Environment("ObjectStore-Test-Co3") // DC names can change, Recommended usage is through environment agnostic VIP like above, see aka.ms/ObjectStore for list of VIPs
            };

            // To specify a particular location use either a Microsoft.ObjectStore.Environment object or a Microsoft.ObjectStore.VIP object
            // The following list tells the library to publish to 3 different ObjectStore endpoints (2 specified using an environment objects and 1 specified using a VIP object)
            // Data written using this configuration will be sent to 3 seperate environments/endpoints

            try
            {
                // The loader will use 20 keys per request, 20 simultenous requests, 10000 ms of timeout per request and a limit of 1000 keys per second
                DataLoadConfiguration config = new DataLoadConfiguration(locations, "testnamespace", "testtable", 20, 20, 2, 10000, 1000, true);
                using (DataLoader loader = new DataLoader(config))
                {
                    KeyType key;
                    ValueType value;
                ​    ContextType context;
                    List<IDataLoadResult> results;
                    while (ReadNextRecord(out key, out value, out context))
                    {
                        // Important: key and value objects are cached until flushed. Changing the contents of key or value before the flush will alter the previously added data
                        loader.Send(key, value, context);
                        results = loader.Receive(false);
                        LogResults(results);
                    }

                    loader.Flush();
                    results = loader.Receive(true);
                    LogResults(results);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex.Message}");
            }


        }


        public static async Task Main(string[] args)
        {
            CommandLine(args);

            var clientBuilder = BuildClient();

            using (client = clientBuilder.Create())
            {
                Console.WriteLine($"Client version is {client.ClientVersion}");

                try
                {
                    for (int iteration = 1; iteration <= iterations; iteration++)
                    {
                        Console.WriteLine($"Iteration: {iteration}");

                        if (writer)
                        {
                            await Waiter();
                            await Writer(TenantId, EnvironmentId);
                        }

                        if (reader)
                        {
                            await Waiter();
                            await Reader(TenantId, EnvironmentId);
                        }

                        if (deleter)
                        {
                            await Waiter();
                            await Deleter(TenantId, EnvironmentId);
                        }

                        if (shower)
                        {
                            await Waiter();
                            await Shower(TenantId, EnvironmentId);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Exception: {ex.Message}");
                }
            }

            PrintStats();
            Console.WriteLine("Press any key to exit");
            Console.ReadKey(true);
        }


        public static string BondToJson(IBondSerializable obj)
        {
            var jsonStream = new MemStream();
            obj.Write(new JsonPrettyWriter(jsonStream));
            jsonStream.Position = 0;
            return new StreamReader(jsonStream).ReadToEnd();
        }

        class TokenGetter
        {
            public async Task<string> GetAADUserToken()
            {
                //Set the scope for API call to user.read
                string[] scopes = new string[] { "api://0cbd5cdb-f433-4fcf-890b-360ca399af06/ObjectStore.Access" };
                AuthenticationResult authResult = null;
                PublicClientApplicationOptions opt = new PublicClientApplicationOptions();
                opt.TenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"; //Microsoft Tenant ID
                opt.ClientId = "0cbd5cdb-f433-4fcf-890b-360ca399af06"; //ObjectStore-User App ID
                opt.RedirectUri = "http://localhost";
                IPublicClientApplication app = PublicClientApplicationBuilder.CreateWithApplicationOptions(opt).Build();
                authResult = await app.AcquireTokenInteractive(scopes)
                    .WithPrompt(Prompt.SelectAccount)
                    .ExecuteAsync();
                if (authResult != null && !string.IsNullOrEmpty(authResult.AccessToken))
                {
                    return authResult.AccessToken;
                }
                throw new Exception("Acquire AAD Token did not return a valid token. Something went wrong in the auth request.");
            }
        }
    }
}