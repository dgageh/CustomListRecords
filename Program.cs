
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
using Guid = System.Guid;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Text;


namespace ListMgmt
{
    class Program
    {

        public const string EnvironmentEndpoint = "https://objectstorebingfd.prod.westus2.binginternal.com:443/sds";// https://objectstorebingfd.int.westus2.binginternal.com:443/sds";
        //Use https://objectstorebingfd.int.westus2.binginternal.com:443/sds URL when code is downloaded/executed from devbox or internet (not AP backend). See more details here: https://eng.ms/docs/experiences-devices/webxt/search-content-platform/objectstore/objectstore/objectstore-public-wiki/getting-started/pf-environments
        public const string NamespaceName = "DynamicsAccountTakeOver";
        public const string TableName = "ListMgmtTest";
        public const StoreName CertificateStoreName = StoreName.My;
        public const StoreLocation CertificateStoreLocation = StoreLocation.CurrentUser;
        public static X509CertificateCollection Certificates = LoadCert();
        public static IClient<Key, Value> client = null;
        public static Dictionary<string, string> header = new Dictionary<string, string>();
        public static string token = string.Empty;
        public static Random random = new Random();
        public static ClientInstrumentation instrumentation = new ClientInstrumentation();
        public static List<(string Operation, long TotalLatency, long ServerSideLatency)> Stats = new List<(string Operation, long TotalLatency, long ServerSideLatency)>();

        class Configuration
        {
            public Configuration(int environment, int list)
            {
                Environment = environment;
                List = list;
            }
            public int Environment { get; set; }
            public int List { get; set; }
        }
        // All the possible combinations of of environmentid, listguid.  The index of this is the argument to the commands.
        static Configuration[] configurations = new Configuration[]
        {
            new Configuration(1,1),
            new Configuration(2,3),
            new Configuration(3,4),
            new Configuration(4,5),
            new Configuration(1,6),
            new Configuration(2,7),
            new Configuration(3,8),
            new Configuration(4,9),
            new Configuration(1,10),
            new Configuration(2,11),
            new Configuration(3,12),
            new Configuration(4,13),
        };

        public static Guid environmentId = Guid.Empty;
        public static Guid listGuid = Guid.Empty;
        public static ushort revision = 0;
   
        enum RecordType
        {
            ListSchema,
            ListRow,
            ListRevisionNum,
            ListCandidateRevision
        }

        struct ListRow
        {
            public string[] Vals; 
        };

        internal class ListRevisionNum
        {
            public ushort Rev {  get; set; }
        }
        
        internal class ListCandidateRevisionNum
        {
            public ushort Rev { get; set; }
        }

        internal class ListSchema
        {
            public string[] Cols { get; set; }
            public string Key   {  get; set; }
            public int ColumnCount {  get; set; }
        }


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
            if (instrumentation.LatencyInfo != null)
                Stats.Add(("Write", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
        }

        static async Task<List<Value>> Read(IEnumerable<Key> keys)
        {
            var result = new List<Value>();
            if (keys.Any())
            {
                result = await client.Read(keys).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
                if (instrumentation.LatencyInfo != null)
                    Stats.Add(("Read", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
            }

            return result;
        }

        static async Task<List<bool>> ContainsKeys(IEnumerable<Key> keys)
        {
            var result = await client.ContainsKeys(keys).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
            if (instrumentation.LatencyInfo != null)
                Stats.Add(("ContainsKeys", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
            return result;
        }

        static async Task Delete(IEnumerable<Key> keys)
        {
            await client.Delete(keys).WithHttpHeaders(header).WithInstrumentation(instrumentation).SendAsync();
            if (instrumentation.LatencyInfo != null)
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
                maxRetries: 0).WithClientVersion(ClientVersion.V2)
                ;


            if (Certificates != null)
            {
                clientBuilder.WithClientCertificates(Certificates);
            }
            return clientBuilder;
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

            if (cols <= 0)
            {
                throw new ArgumentException($"--columns must be specified > 0");
            }
            return cols;
        }

        private static int RequireColumn()
        {
            int col = myCommands["--column"].Value;

            if (col <= 0)
            {
                throw new ArgumentException($"--column must be specified > 0");
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

        private static Guid GuidFromInt(string type, int digit)
        {
            if (digit < 1 || digit > 9)
            {
                throw new ArgumentException($"{type} id must be in the range 1-9.");
            }

            string phonyGuid = new string(digit.ToString()[0], 32);

            // Convert the string into a GUID format: "00000000-0000-0000-0000-000000000000"
            return new Guid(phonyGuid.Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"));
        }
        private static Guid RequireValidList(int digit)
        {
            return GuidFromInt("List", digit);
        }
        private static Guid RequireValidEnvironment(int digit)
        {
            return GuidFromInt("Environment", digit);
        }

        private static async Task RequireValidKeyFields(int environment, int list)
        {
            listGuid = RequireValidList(list);
            environmentId = RequireValidEnvironment(environment);
            revision = await GetRevision();
        }

        static long RecCount = 0;

        static void LogResults(IEnumerable<IDataLoadResult> results)
        {
            foreach (var result in results)
            {
                if (result.IsSuccessful)
                {
                    RecCount++;
                    if (RecCount % 10000 == 0)
                        Console.Write(".");

                    if (RecCount % 100000 == 0)
                        Console.WriteLine(result.Context);
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

        private static string MakeSchemaRecord(int columns)
        {
            string columnValue = string.Empty;
            ListSchema schema = new ListSchema()
            {
                Cols = new string[columns],
                ColumnCount = columns,
            };

            for (int i = 0; i < columns; i++)
            {
                schema.Cols[i] = $"List{listGuid}Col{i}";
            }
            schema.Key = schema.Cols[0];
            columnValue = JsonConvert.SerializeObject(schema);
            return columnValue;
        }

        private static string MakeListRecord(string operation, int columns)
        {
            string columnValue = string.Empty;
            ListRow rec = new ListRow()
            {
                Vals = new string[columns],
            };

            for (int i = 0; i < columns; i++)
            {
                rec.Vals[i] = $"{operation} Col {i} {DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff")}";
            }
            columnValue = JsonConvert.SerializeObject(rec);
            return columnValue;
        }


        // TODO: For imports, he has to increment the revision before he writes anything.

        private static async Task<(Key, Value)> MakeImportRecord(string operation, int recNo, int columns)
        {
            var key = MakeRowKey(recNo, recNo == 0 ? RecordType.ListSchema : RecordType.ListRow);
            
            Value value = new Value();

            string columnValue = string.Empty;
            if (recNo == 0)
            {
                columnValue = MakeSchemaRecord(columns);
            }
            else
            {
                columnValue = MakeListRecord(operation, columns);
            }
            value.JsonData = new BondBlob(Encoding.UTF8.GetBytes(columnValue));    // Not sure what the right encoding is here.

            await Task.Delay(0);

            return (key, value);
        }

        private static async Task<(Key, Value)> MakeUpsertRecord(string operation, int recNo, int columns)
        {
            var key = MakeRowKey(recNo, RecordType.ListRow);

            var value = (await Read(new[] { key })).FirstOrDefault() ?? new Value();

            var listRow = JsonConvert.DeserializeObject<ListRow>(Encoding.UTF8.GetString(value.JsonData.Data.ToArray<byte>()));

            for (int i = 0; i < columns; i++)
            {
                listRow.Vals[i] = $"{operation} Col {i} {DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff")}";
            }

            value.JsonData = new BondBlob(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(listRow)));

            return (key, value);
        }


        public const string EnvironmentVip = "https://objectstorebingfd.prod.westus2.binginternal.com:443/sds"; // https://objectstorefd.prod.westus2.binginternal.com:443/sds/ObjectStoreQuery/V1";
        // Use https://objectstorebingfd.prod.westus2.binginternal.com:443/sds URL when code is downloaded/executed from devbox or internet (not AP backend). See more details here: https://eng.ms/docs/experiences-devices/webxt/search-content-platform/objectstore/objectstore/objectstore-public-wiki/getting-started/pf-environments
        // prod "https://objectstorebingfd.prod.westus2.binginternal.com:443/sds";

        private static async Task DoBulkWrite(string operation, int startRow, int rows, int columns, Func<string, int, int, Task<(Key, Value)>> recordGenerator)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            int endRow = startRow == 0 ? startRow + rows + 1 : startRow + rows;  // If updating the schema, must add one.
            stopwatch.Stop();
            stopwatch.Reset();
            var locations = new List<ITableLocation>
            {
                new VIP(EnvironmentVip)
            };

            // The loader will use 20 keys per request, 20 simultenous requests, 10000 ms of timeout per request and a limit of 2000 keys per second
            var config = new DataLoadConfiguration(locations, NamespaceName, TableName, 50, 20, 2, 20000, 4000, true).WithClientCertificates(Certificates);
            using (var loader = new DataLoader(config))
            {
                for (int recNo = startRow; recNo <= endRow; recNo++)
                {
                    (var key, var value) = await recordGenerator(operation, recNo, columns);
                    object context = recNo;
                    stopwatch.Start();
                    loader.Send(key, value, context);
                    var results = loader.Receive(waitForAllRequests: false);
                    stopwatch.Stop();
                    LogResults(results);
                }

                stopwatch.Start();
                loader.Flush();
                var finalResults = loader.Receive(waitForAllRequests: true);
                stopwatch.Stop();
                LogResults(finalResults);
            }
            Stats.Add((operation, stopwatch.ElapsedMilliseconds, 0));
        }

        private static async Task TestRangeQuery(Key startKey, Key endKey)
        {
            List<KeyValuePair<Key, Value>> allResults = new List<KeyValuePair<Key, Value>>();

            var rangeRequest = client.RangeQueryBroadcast(startKey, endKey).WithKeysOnly().WithInstrumentation(instrumentation);

            // WithCustomShardResultLimit() is used to illustrate the use of continuation query on the small amount of data 
            // present in the test table, it is generally not needed otherwise
            //            var queryResult = await rangeRequest.WithCustomShardResultLimit(1).SendAsync();
            var queryResult = await rangeRequest.SendAsync();

            while (!queryResult.IsFinished && queryResult.Results.Any())
            {
                Console.WriteLine($"Continuing after {queryResult.Results.Count}");
                queryResult = await ExecuteContinuation(queryResult);
            }

            foreach (var result in queryResult.Results)
            {
                Console.WriteLine($"Rev {result.Key.Ids.Revision} Type {(RecordType)result.Key.RecType} {result.Key.ListKey}");
            }

            if (instrumentation.LatencyInfo != null)
                Stats.Add(("RangeQuery", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
        }

        private static async Task<RangeQueryResults<Key, Value>> ExecuteContinuation(RangeQueryResults<Key, Value> previousResults)
        {
            foreach (var result in previousResults.Results)
            {
                Console.WriteLine($"Rev {result.Key.Ids.Revision} Type {(RecordType)result.Key.RecType} {result.Key.ListKey}");
            }
            return await client.ContinueRangeQueryBroadcast(previousResults.CreateContinuationParameters(), previousResults.EndKey).SendAsync();
        }


        private static async Task RangeBulkDelete(Key startKey, Key endKey)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            stopwatch.Stop();
            stopwatch.Reset();
            var locations = new List<ITableLocation>
            {
                new VIP(EnvironmentVip)
            };

            // The loader will use 20 keys per request, 20 simultenous requests, 10000 ms of timeout per request and a limit of 1000 keys per second
            var config = new DataLoadConfiguration(locations, NamespaceName, TableName, 50, 20, 2, 20000, 4000, true).WithClientCertificates(Certificates);
            using (var loader = new DataLoader(config))
            {
                List<KeyValuePair<Key, Value>> allResults = new List<KeyValuePair<Key, Value>>();

                var rangeRequest = client.RangeQueryBroadcast(startKey, endKey).WithKeysOnly().WithInstrumentation(instrumentation);

                // WithCustomShardResultLimit() is used to illustrate the use of continuation query on the small amount of data 
                // present in the test table, it is generally not needed otherwise
                //            var queryResult = await rangeRequest.WithCustomShardResultLimit(1).SendAsync();
                var queryResult = await rangeRequest.SendAsync();

                while (queryResult.Results.Any())
                {
                    foreach (var pair in queryResult.Results)
                    {
                        var key = pair.Key;
                        object context = key.ListKey;
                        stopwatch.Start();
                        loader.Delete(key, context);
                        var results = loader.Receive(waitForAllRequests: false);
                        stopwatch.Stop();
                        LogResults(results);
                    }

                    if (queryResult.IsFinished)
                        break;

                    queryResult = await ExecuteDeleteContinuation(queryResult);
                } 

                stopwatch.Start();
                loader.Flush();
                var finalResults = loader.Receive(waitForAllRequests: true);
                stopwatch.Stop();
                LogResults(finalResults);
            }
            Stats.Add(("Bulk Delete", stopwatch.ElapsedMilliseconds, 0));
            if (instrumentation.LatencyInfo != null)
                Stats.Add(("RangeQuery", instrumentation.LatencyInfo.GetTotalLatency(), instrumentation.LatencyInfo.GetServerSideLatency()));
        }

        private static async Task<RangeQueryResults<Key, Value>> ExecuteDeleteContinuation(RangeQueryResults<Key, Value> previousResults)
        {
            //foreach (var result in previousResults.Results)
            //{
            //    Console.WriteLine($"Rev {result.Key.Ids.Revision} Type {(RecordType)result.Key.RecType} {result.Key.ListKey}");
            //}
            return await client.ContinueRangeQueryBroadcast(previousResults.CreateContinuationParameters(), previousResults.EndKey).SendAsync();
        }


        private static async Task DoBulkDelete(string operation, int startRow, int rows, Func<int, RecordType, Key> keyGenerator)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            stopwatch.Stop();
            stopwatch.Reset();
            var locations = new List<ITableLocation>
            {
                new VIP(EnvironmentVip)
            };

            // The loader will use 20 keys per request, 20 simultenous requests, 10000 ms of timeout per request and a limit of 1000 keys per second
            var config = new DataLoadConfiguration(locations, NamespaceName, TableName, 20, 20, 2, 10000, 1000, true).WithClientCertificates(Certificates);
            using (var loader = new DataLoader(config))
            {
                for (int recNo = startRow; recNo < startRow + rows; recNo++)
                {
                    var key = keyGenerator(recNo, recNo == 0 ? RecordType.ListSchema : RecordType.ListRow);
                    object context = recNo;
                    stopwatch.Start();
                    loader.Delete(key, context);
                    var results = loader.Receive(waitForAllRequests: false);
                    stopwatch.Stop();
                    LogResults(results);
                }

                stopwatch.Start();
                loader.Flush();
                var finalResults = loader.Receive(waitForAllRequests: true);
                stopwatch.Stop();
                LogResults(finalResults);
            }
            Stats.Add((operation, stopwatch.ElapsedMilliseconds, 0));
            await Task.Delay(0);
        }

        private static string Context()
        {
            return $"Environment {environmentId} List {listGuid}";
        }

        private static async Task<ushort> GetRevision()
        {
            var key = MakeRowKey(0, RecordType.ListRevisionNum);
            var value = (await Read(new[] { key })).FirstOrDefault();

            if (value == null)
            if (value == null)
                return 0;

            var listRevisionNum = JsonConvert.DeserializeObject<ListRevisionNum>(Encoding.UTF8.GetString(value.JsonData.Data.ToArray<byte>()));

            if (listRevisionNum == null)
                return 0;

            return listRevisionNum.Rev;
        }

        private static async Task SetRevision(bool candidate, ushort rev)
        {
            var key = MakeRowKey(0, candidate? RecordType.ListCandidateRevision: RecordType.ListRevisionNum);
            string serializedRec = string.Empty;

            if (candidate)
            {
                var listCandidateRevisionNum = new ListCandidateRevisionNum()
                {
                    Rev = rev
                };
                serializedRec = JsonConvert.SerializeObject(listCandidateRevisionNum);
            }
            else
            {
                var listRevisionNum = new ListRevisionNum()
                {
                    Rev = rev
                };
                serializedRec = JsonConvert.SerializeObject(listRevisionNum);

            }
            var value = new Value()
            {
                JsonData = new BondBlob(Encoding.UTF8.GetBytes(serializedRec))    // Not sure what the right encoding is here.
            };
            KeyValuePair<Key, Value> kvp = new KeyValuePair<Key, Value>(key, value);

            await Write(new[] { kvp });
        }

        private static async Task DeleteCandidateRevision()
        {
            var key = MakeRowKey(0, RecordType.ListCandidateRevision);

            await Delete(new[] { key });
        }

        private static async Task BulkImporter(int environment, int list)
        {
            (int rows, int columns) = RequireRowsAndColumns();

            await RequireValidKeyFields(environment, list);

            Console.WriteLine($"Bulk Importing {rows} Rows and {columns} Columns into {Context()}");

            revision++;                                
            await SetRevision(true, revision);        // Create the candidate revision
            
            await DoBulkWrite("import", 0, rows, columns, MakeImportRecord);  // Starts at 0.  Create the schema record.

            await SetRevision(false, revision);         // Create the realrevision
            await DeleteCandidateRevision();
        }

        // Upsert values into the first n columns of n rows starting at row n
        private static async Task BulkUpserter(int envivronment, int list)
        {
            (int rows, int columns) = RequireRowsAndColumns();

            int row = RequireRow();

           await RequireValidKeyFields(envivronment, list);

            Console.WriteLine($"Bulk Upserting {rows} Rows into {Context()}");

            await DoBulkWrite("upsert", row, rows, columns, MakeUpsertRecord);
        }

        private static async Task BulkDeleter(int environment, int list)
        {
            int rows = RequireRows();

            await RequireValidKeyFields(environment, list);

            Console.WriteLine($"Bulk Deleting {rows} Rows  from {Context()}");

            await DoBulkDelete("bulk delete", 1, rows, MakeRowKey);
        }

        // Delete the whole list -- even the schema.
        private static async Task RangeDelete(int environment, int list)
        {
            await RequireValidKeyFields(environment, list);
            int row = RequireRow();
            int rows = RequireRows();

            Console.WriteLine($"Bulk Deleting {Context()}");

            var key1 = MakeRowKey(row, RecordType.ListRow);
            var key2 = MakeRowKey(row + rows - 1, RecordType.ListRow);


            Console.WriteLine("Env {0}", GuidFromParts(key1.Ids.EnvironmentId.Low, key1.Ids.EnvironmentId.High));
            Console.WriteLine("Env {0}", GuidFromParts(key2.Ids.EnvironmentId.Low, key2.Ids.EnvironmentId.High));
            Console.WriteLine("List {0}", GuidFromParts(key1.Ids.ListId.Low, key1.Ids.ListId.High));
            Console.WriteLine("List {0}", GuidFromParts(key2.Ids.ListId.Low, key2.Ids.ListId.High));


            await RangeBulkDelete(key1, key2);
        }

        private static async Task QueryList(int environment, int list)
        {
            await RequireValidKeyFields(environment, list);
            int row = RequireRow();
            int rows = RequireRows();

            Console.WriteLine($"Querying List {Context()}");

            var key1 = MakeRowKey(row, RecordType.ListRow);
            var key2 = MakeRowKey(row+rows-1, RecordType.ListRow);


            Console.WriteLine("Env {0}", GuidFromParts(key1.Ids.EnvironmentId.Low, key1.Ids.EnvironmentId.High));
            Console.WriteLine("Env {0}", GuidFromParts(key2.Ids.EnvironmentId.Low, key2.Ids.EnvironmentId.High));
            Console.WriteLine("List {0}", GuidFromParts(key1.Ids.ListId.Low, key1.Ids.ListId.High));
            Console.WriteLine("List {0}", GuidFromParts(key2.Ids.ListId.Low, key2.Ids.ListId.High));

            await TestRangeQuery(key1, key2);
        }


        private static Key MakeRowKey(int recNo, RecordType recordType)
        {
            GuidToParts(listGuid, out ulong listPart1, out ulong listPart2);
            GuidToParts(environmentId, out ulong envPart1, out ulong envPart2);

            int forcerevision = myCommands["--revision"].Value;
            if (forcerevision > 0)
            {
                Console.WriteLine($"Forcing revision to {forcerevision}");
                revision = (ushort)forcerevision;
            }

            Key key = new Key()
            {
                Ids = new PartitionedKeyFields()
                {
                    ListId = new BondGuid()
                    {
                        High = listPart1,
                        Low = listPart2,
                    },
                    EnvironmentId = new BondGuid()
                    {
                        High = envPart1,
                        Low = envPart2,
                    },
                    Revision = (recordType == RecordType.ListRevisionNum || recordType == RecordType.ListCandidateRevision) ? (ushort)0 : revision,
                },
                ListKey = recNo.ToString().PadLeft(10, '0'), // Format the recNo as a string padded left to 10 digits
                RecType = Convert.ToByte(recordType),
            };

            return key;
        }

        private static async Task BulkReader(int environment, int list)
        {
            int rows = RequireRows();
            int startRow = RequireRow();

            await RequireValidKeyFields(environment, list);

            Console.WriteLine($"Bulk Reading the first {rows} Keys from {Context()}");
            List<Key> keys = new List<Key>(rows);
            for (int row = startRow; row <= startRow + rows; row++)
            {
                keys.Add(MakeRowKey(row, row == 0 ? RecordType.ListSchema : RecordType.ListRow));
            }

            var values = await Read(keys);

            int keyCount = keys.Count();
            int valueCount = values.Count();

            Console.WriteLine($"Read the values for {keyCount} Keys.  Returned {valueCount} values.");
            foreach (var value in values)
            {
                Console.WriteLine(Encoding.UTF8.GetString(value.JsonData.Data.ToArray<byte>()));
            }
        }

        private static async Task<(Key key, Value value)> DoRead(int row, int column)
        {
            Console.WriteLine($"Reading Row {row}, Column {column} from {Context()}");

            var key = MakeRowKey(row, row == 0 ? RecordType.ListSchema : RecordType.ListRow);

            var value = (await Read(new[] { key })).FirstOrDefault();

            return (key, value);
        }

        private static async Task Reader(int environment, int list)
        {
            (int row, int column) = RequireRowAndColumn();
            await RequireValidKeyFields(environment, list); 
            
            string colVal = string.Empty;

            (var key, var value) = await DoRead(row, column);

            if (value != null) 
            {
                var listRow = JsonConvert.DeserializeObject<ListRow>(Encoding.UTF8.GetString(value.JsonData.Data.ToArray<byte>()));

                colVal = listRow.Vals[column-1];
                Console.WriteLine($"Key {key.ListKey} Value {colVal}");
            }
            else
            {
                Console.WriteLine($"Key {key.ListKey} Not found.");
            }
        }

        private static async Task Updater(int environment, int list)
        {
            (int row, int column) = RequireRowAndColumn();

            await RequireValidKeyFields(environment, list); 

            string oldValue = string.Empty;

            Console.WriteLine($"Updating Row {row}, Column {column} of {Context()}");

            (var key, var value) = await DoRead(row, column);

            if (value != null)  
            {
                var listRow = JsonConvert.DeserializeObject<ListRow>(Encoding.UTF8.GetString(value.JsonData.Data.ToArray<byte>()));
                oldValue = listRow.Vals[column-1];

                string newValue = $"update Col {column} {DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff")}";

                listRow.Vals[column-1] = newValue;

                value.JsonData = new BondBlob(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(listRow)));

                KeyValuePair<Key, Value> kvp = new KeyValuePair<Key, Value>(key, value);

                await Write(new[] { kvp });

                Console.WriteLine($"Key {key.ListKey} Old Value {oldValue} New Value {newValue}");
            }
            else
                Console.WriteLine($"Key {key.ListKey} Nothing found to update.");
        }

        private static async Task Deleter(int environment, int list)
        {
            int row = RequireRow();
            int rows = RequireRows();

            await RequireValidKeyFields(environment, list);

            for (int i = row; i < row + rows; i++)
            {


                var key = MakeRowKey(i, row == 0 ? RecordType.ListSchema : RecordType.ListRow);

    //            Console.WriteLine($"Deleting Row {row} of {Context()} Key {key.ListKey}");

                var containsKeys = await ContainsKeys(new[] { key });

                if (containsKeys.FirstOrDefault())
                {
                    Console.WriteLine($"FoundKey {key.ListKey}");
                    await Delete(new[] { key });
                }
            }
        }

        private static async Task<bool> TryInvoke(string command, Func<int, int, Task> function)
        {
            try
            {
                int argument = myCommands[command].Value;

                if (argument > 0)
                {
                    await Waiter();

                    await function(configurations[argument-1].Environment, configurations[argument-1].List);
                    Console.WriteLine($"{command} executed successfully.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{command} failed with error: {ex.Message}");
            }
            return false;
        }

        internal class MyCommandOptions
        {
            public CommandOption CommandOption { get; set; }
            public string Description { get; set; }
            public bool IsNumeric { get; set; }
            public int Value { get; set; }
            public string StringValue { get; set; }
            public Func<int, int, Task> Implementer { get; set; }
        }
        static Dictionary<string, MyCommandOptions> myCommands = new Dictionary<string, MyCommandOptions>();

        static void AddCommandOption(CommandLineApplication app, bool isNumeric, string command, string description, Func<int, int, Task> implementer = null)
        {
            string cmdLineOption = $"--{command}";
            var option = app.Option(cmdLineOption, description, CommandOptionType.SingleValue);
            myCommands.Add(cmdLineOption, new MyCommandOptions { CommandOption = option, Description = description, Value = 0, IsNumeric = isNumeric, StringValue = null, Implementer = implementer });
        }

        static void CommandLine(string[] args)
        {
            var app = new CommandLineApplication();

            // Define options
            app.HelpOption("-? | --help");

            AddCommandOption(app, true, "bulk-import", "Uses Point Dataloader. Data is generated. Specify which list Guid to import. Imports n rows and n columns.", BulkImporter);
            AddCommandOption(app, true, "bulk-upsert", "Uses Point Dataloader. Data is generated. Specify which list to upsert keys into. Upserts n rows and n columns starting at given row", BulkUpserter);
            AddCommandOption(app, true, "bulk-delete", "Uses Point Dataloader. Specify which list to delete keys from. Deletes n rows.", BulkDeleter);
            AddCommandOption(app, true, "read-keys", "Specify which list to read keys from.", BulkReader);
            AddCommandOption(app, true, "delete-list", "Uses Range Queries. Specify which list to delete.", RangeDelete);
            AddCommandOption(app, true, "query-list", "Uses Range Queries to query list n at row row for rows rows. ", QueryList);
            AddCommandOption(app, true, "read-key", "Reads the key at row/col from list n", Reader);
            AddCommandOption(app, true, "update-key", "Reads and updates the key at row/col from list. Data is generated.", Updater);
            AddCommandOption(app, true, "delete-key", "Deletes the key at row/col from list n", Deleter);
            AddCommandOption(app, true, "rows", "How many rows");
            AddCommandOption(app, true, "columns", "How many columns");
            AddCommandOption(app, true, "row", $"Operates on the key at the given row.");
            AddCommandOption(app, true, "column", $"Operates on the key at the given col.");
            AddCommandOption(app, true, "revision", $"Operates on the key with the given revision number.");
            AddCommandOption(app, true, "wait", "Wait for n miliseconds after each operation");

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
                        if (kvp.Value.IsNumeric)
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
                        else
                        {
                            kvp.Value.StringValue = kvp.Value.CommandOption.Value();
                            Console.WriteLine($"{kvp.Key} is {kvp.Value.StringValue}");
                        }
                    }
                }
                return 0;
            });

            app.Execute(args);
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
                    foreach (var kvp in myCommands)
                    {
                        if (kvp.Value.Implementer != null)
                        {
                            if (await TryInvoke(kvp.Key, kvp.Value.Implementer))
                                break;  // One command per execution
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Exception: {ex.Message}");
                }
            }

            PrintStats();
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