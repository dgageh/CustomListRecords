
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
using System.Drawing.Text;
using System.Data.Common;
using System.Net;


namespace CustomListPoc
{
    class Program
    {

        public const string EnvironmentEndpoint = "https://objectstorebingfd.int.westus2.binginternal.com:443/sds";
        //Use https://objectstorebingfd.int.westus2.binginternal.com:443/sds URL when code is downloaded/executed from devbox or internet (not AP backend). See more details here: https://eng.ms/docs/experiences-devices/webxt/search-content-platform/objectstore/objectstore/objectstore-public-wiki/getting-started/pf-environments
        public const string NamespaceName = "DFP-CRE";
        public const string TableName = "CustomListRecords";
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
            int waitfor = myCommands["--wait"].Value;
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
            public Func<int, Task> Implementer { get; set; }
        }
        static Dictionary<string, MyCommandOptions> myCommands = new Dictionary<string, MyCommandOptions>();
        
        static void AddCommandOption(CommandLineApplication app, string command,  string description, Func<int, Task> implementer = null )
        {
            string cmdLineOption = $"--{command}";
            var option = app.Option(cmdLineOption, description, CommandOptionType.SingleValue);
            myCommands.Add(cmdLineOption, new MyCommandOptions { CommandOption = option, Description = description, Value = 0, Implementer = implementer });
        }

        static void CommandLine(string[] args)
        {
            var app = new CommandLineApplication();

            // Define options
            app.HelpOption("-? | --help");

            AddCommandOption(app, "import-list", "Specify which list Guid to import", BulkImporter);
            AddCommandOption(app, "delete-list","Specify which list to delete", BulkReader);
            AddCommandOption(app, "read-keys","Specify which list to read keys from", BulkReader);
            AddCommandOption(app, "upsert-keys","Specify which list to read keys from", BulkUpserter);
            AddCommandOption(app, "rows","How many rows");
            AddCommandOption(app, "columns","How many columns");
            AddCommandOption(app, "read-key","Reads the key at row/col from list n", Reader);
            AddCommandOption(app, "update-key","Reads and updates the key at row/col from list", Updater );
            AddCommandOption(app, "delete-key","Deletes the key at row/col from list n", Deleter);
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


        /*
         *             AddCommandOption(app, "import-list", "Specify which list Guid to import");
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
         */

        private static (Key, Value) MakeImportRecord(Guid listGuid, int listNum, int recNo, int columns)
        {
            GuidToParts(listGuid, out ulong part1, out ulong part2);

            Key key = new Key()
            {
                ListId = new CustomList.Guid
                {
                    ListIdHigh = part1,
                    ListIdLow = part2
                },
                ListKey = $"List{listNum}Rec{recNo}"
            };

            Value value = new Value()
            {
                Column1 = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                Column2 = columns >= 2 ? DateTime.Now.ToString() : null,
                Column3 = columns >= 3 ? DateTime.Now.ToString() : null,
                Column4 = columns >= 4 ? DateTime.Now.ToString() : null,
                Column5 = columns >= 5 ? DateTime.Now.ToString() : null,
                Column6 = columns >= 6 ? DateTime.Now.ToString() : null,
                Column7 = columns >= 7 ? DateTime.Now.ToString() : null,
                Column8 = columns >= 8 ? DateTime.Now.ToString() : null,
                Column9 = columns >= 9 ? DateTime.Now.ToString() : null,
                Column10 = columns >= 10 ? DateTime.Now.ToString() : null,
            };

            return (key, value);   
        }
        private static Key MakeReadKey(Guid listGuid, int listNum, int recNo)
        {
            GuidToParts(listGuid, out ulong part1, out ulong part2);

            Key key = new Key()
            {
                ListId = new CustomList.Guid
                {
                    ListIdHigh = part1,
                    ListIdLow = part2
                },
                ListKey = $"List{listNum}Rec{recNo}"
            };

            return key;
        }



        private static (int, int) RequireRowsAndColumns()
        {
            int rows = RequireRows();
            int columns = RequireColumns();
            return (rows, columns);
        }

        private static int RequireRows()
        {
            int rows = myCommands["--rows"].Value;

            if (rows <= 0)
            {
                throw new ArgumentException("--rows must be specified > 0");
            }
            return rows;
        }

        private static int RequireColumns()
        {
            int cols = myCommands["--columns"].Value;

            if (cols <= 0 || cols > 10)
            {
                throw new ArgumentException("--columns must be specified > 0 and <= 10");
            }
            return cols;
        }

        private static int RequireColumn()
        {
            int col = myCommands["--column"].Value;

            if (col <= 0 || col > 10)
            {
                throw new ArgumentException("--column must be specified > 0 and <= 10");
            }
            return col;
        }

        private static int RequireRow()
        {
            int row = myCommands["--row"].Value;

            if (row <= 0)
            {
                throw new ArgumentException("--row must be specified > 0");
            }
            return row;
        }

        private static (int, int) RequireRowAndColumn()
        {
            int row = RequireRow();
            int column = RequireColumn();

            return (row, column);
        }

        private static Guid RequireValidList(int digit)
        {
            if (digit < 1 || digit > 9)
            {
                throw new ArgumentException("List id must be in the range 1-9.");
            }

            string phonyGuid = $"{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}{digit}";

            // Convert the string into a GUID format: "00000000-0000-0000-0000-000000000000"
            return new Guid(phonyGuid.Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"));
        }

        static void LogResults(IEnumerable<IDataLoadResult> results)
        {
            foreach (var result in results)
            {
                if (result.IsSuccessful)
                {
                    Console.WriteLine("Record {0}: writing to all locations successful", result.Context);
                }
                else
                {
                    Console.WriteLine("Record {0}: writing failed to {1} locations: {2}",
                        result.Context,
                        result.FailedLocations.Count,
                        string.Join(", ", result.FailedLocations));
                }
            }
        }

        public const string EnvironmentVip = "https://objectstorebingfd.prod.westus2.binginternal.com:443/sds";
        //Use https://objectstorebingfd.prod.westus2.binginternal.com:443/sds URL when code is downloaded/executed from devbox or internet (not AP backend). See more details here: https://eng.ms/docs/experiences-devices/webxt/search-content-platform/objectstore/objectstore/objectstore-public-wiki/getting-started/pf-environments

        private static void BulkImporter(int list)
        {
            (int rows, int columns) = RequireRowsAndColumns();
            
            Guid listGuid = RequireValidList(list);

            Console.WriteLine($"Bulk Importing {rows} Rows and {columns} Columns into List {listGuid}");

            var locations = new List<ITableLocation>
            {
                new VIP(EnvironmentVip)
            };

            // The loader will use 20 keys per request, 20 simultenous requests, 10000 ms of timeout per request and a limit of 1000 keys per second
            var config = new DataLoadConfiguration(locations, NamespaceName, TableName, 20, 20, 2, 10000, 1000, true);
            using (var loader = new DataLoader(config))
            {
                for (int row = 0; row < rows; row++)
                {
                    (var key, var value) = MakeImportRecord(listGuid, list, rows, columns);
                    object context = row;
                    loader.Send(key, value, context);
                    var results = loader.Receive(waitForAllRequests: false);
                    LogResults(results);
                }

                loader.Flush();
                var finalResults = loader.Receive(waitForAllRequests: true);
                LogResults(finalResults);
            }
        }

        private static async Task BulkDeleter(int list)
        {
            Guid listGuid = RequireValidList(list);

            Console.WriteLine($"Bulk Deleting List {listGuid}");

            // TODO: Requires Range Queries

        }
        private static async Task BulkReader(int list)
        {
            int rows = RequireRows();
            Guid listGuid = RequireValidList(list);
            Console.WriteLine($"Bulk Reading the first {rows} Keys from List {listGuid}");
            List<Key> keys = new List<Key>(rows);
            for (int row = 1; row <= rows; row++)
            {
                keys.Add(MakeReadKey(listGuid, list, row));
            }

            var values = await Read(keys);

            int keyCount = keys.Count();
            int valueCount = values.Count();

            Console.WriteLine($"Read the values for {keyCount} Keys.  Returned {valueCount} values.");
        }

        private static async Task BulkUpserter(int list)
        {
            (int rows, int columns) = RequireRowsAndColumns();
            Guid listGuid = RequireValidList(list);

            Console.WriteLine($"Bulk Upserting {rows} Rows into List {listGuid}");
        }
        private static async Task Reader(int list)
        {
            (int row, int column) = RequireRowAndColumn();
            Guid listGuid = RequireValidList(list);

            Console.WriteLine($"Reading Row {row}, Column {column} from List {listGuid}");

            var key = MakeReadKey(listGuid, list, row);

            var values = await Read(new[] { key });

            string value = (string)typeof(Value).GetProperty("Column{column}").GetValue(values[0]);

            Console.WriteLine($"Key {key.ListKey} Value {value}");
        }

        private static async Task Updater(int list)
        {
            (int row, int column) = RequireRowAndColumn();
            Guid listGuid = RequireValidList(list);

            Console.WriteLine($"Updating Row {row}, Column {column} of List {listGuid}");

        }
        private static async Task Deleter(int list)
        {
            int row = RequireRow();
            Guid listGuid = RequireValidList(list);
            Console.WriteLine($"Deleting Row {row} of List {listGuid}");
        }

        private static async Task TryInvoke(string command, Func<int, Task> function)
        {
            try
            {
                int argument = myCommands[command].Value;

                if (argument > 0)
                {
                    await Waiter();
                    await function(argument);
                    Console.WriteLine($"{command} executed successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{command} failed with error: {ex.Message}");
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
                        foreach (var kvp in myCommands)
                        {
                            if (kvp.Value.Implementer != null)
                            {
                                await TryInvoke(kvp.Key, kvp.Value.Implementer);
                            }
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