using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Win32;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Text.Json.Serialization;

namespace InstallationUtility
{

    [JsonSerializable(typeof(InstallationCodeStatus))]
    public partial class AppJsonSerializerContext : JsonSerializerContext
    {
    }

    public class InstallationCodeStatus
    {
        public string status { get; set; }
        public string installationCode { get; set; }
    }

    public class Program
    {
        // You should replace this with your actual Firestore API endpoint
        private const string API_BASE_URL = "https://us-central1-pcmon-337e3.cloudfunctions.net";

        // Registry path where the installation code will be stored
        private const string REGISTRY_KEY_PATH = @"SOFTWARE\MyCompany\MyApp";
        private const string REGISTRY_VALUE_NAME = "InstallationCode";
        private const string REGISTRY_DEBUG_PATH = @"SOFTWARE\MyCompany\MyApp\Debug";

        // Name of the encrypted file to store the installation code
        private const string ENCRYPTED_FILE_NAME = "installcode.dat";

        public static async Task<int> Main(string[] args)
        {
            //Console.WriteLine("VALIDATION_FAILED=1");
            //return 0;

            // Create a crash dump log path in a location we're sure we can write to
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string logFolderPath = Path.Combine(appDataPath, "MyApp", "Logs");
            string logFilePath = Path.Combine(logFolderPath, "InstallationUtility.log");
            string codeValidationFailureFlagPath = Path.Combine(logFolderPath, "cvf.flag");
            string codeWritingFailureFlagPath = Path.Combine(logFolderPath, "cwf.flag");
            string codeStatusUpdateFailureFlagPath = Path.Combine(logFolderPath, "csuf.flag");

            try
            {
                // Make sure log directory exists
                Directory.CreateDirectory(logFolderPath);

                // Log basic info about this run
                File.AppendAllText(logFilePath, $"\n\n--------------------\n");
                File.AppendAllText(logFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] InstallationUtility starting\n");
                File.AppendAllText(logFilePath, $"Args: {string.Join(" ", args)}\n");
                File.AppendAllText(logFilePath, $"Username: {Environment.UserName}\n");
                File.AppendAllText(logFilePath, $"Running from: {Assembly.GetExecutingAssembly().Location}\n");
                File.AppendAllText(logFilePath, $"Working dir: {Environment.CurrentDirectory}\n");
                File.AppendAllText(logFilePath, $"Is64BitProcess: {Environment.Is64BitProcess}\n");
            }
            catch (Exception ex)
            {
                // If we can't write to the log file, try registry debugging instead
                try
                {
                    using (var debugKey = Registry.LocalMachine.CreateSubKey(REGISTRY_DEBUG_PATH))
                    {
                        debugKey.SetValue("StartupError", ex.Message);
                        debugKey.SetValue("LastRun", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        debugKey.SetValue("CommandLine", string.Join(" ", args));
                        debugKey.SetValue("UserName", Environment.UserName);
                        debugKey.SetValue("ProcessID", Process.GetCurrentProcess().Id);
                        debugKey.SetValue("ExePath", Assembly.GetExecutingAssembly().Location ?? "Unknown");
                        debugKey.SetValue("WorkingDir", Environment.CurrentDirectory);
                    }
                }
                catch
                {
                    // Nothing we can do if we can't log
                }
            }

            try
            {
                WriteToLog(logFilePath, "Processing command");

                if (args.Length < 1)
                {
                    WriteToLog(logFilePath, "Error: No command specified");
                    //Console.Error.WriteLine("Error: No command specified.");
                    return 1;
                }

                string command = args[0].ToLower();
                WriteToLog(logFilePath, $"Command: {command}");

                switch (command)
                {
                    case "valres":
                        Console.WriteLine("VALIDATION_FAILED=1");
                        return 0;

                    case "validate":
                        Cleanup(logFilePath, codeValidationFailureFlagPath, codeWritingFailureFlagPath, codeStatusUpdateFailureFlagPath);

                        if (args.Length < 2)
                        {
                            WriteToLog(logFilePath, "Error: Installation code required for validation");
                            //Console.Error.WriteLine("Error: Installation code required for validation.");
                            return 1;
                        }
                        string validateCode = args[1];
                        WriteToLog(logFilePath, $"Validating installation code: {validateCode}");
                        bool result = await ValidateInstallationCodeWithRetry(validateCode, logFilePath);
                        WriteToLog(logFilePath, $"Validation result: {result}");

                        if (!result)
                        {
                            File.AppendAllText(codeValidationFailureFlagPath, $"\n\n--------------------\n");
                        }
                        Thread.Sleep(2500);
                  
                        //Console.WriteLine("VALIDATION_FAILED=1");
                        return 1603;

                    case "write":
                        if (args.Length < 3)
                        {
                            WriteToLog(logFilePath, "Error: Installation code and install path required");
                           // Console.Error.WriteLine("Error: Installation code and install path required.");
                            return 1;
                        }
                        string writeCode = args[1];
                        string installPath = args[2];
                        WriteToLog(logFilePath, $"Writing installation code: {writeCode} to {installPath}");
                        bool resultWrite = WriteInstallationCode(writeCode, installPath, logFilePath);
                        if (!resultWrite)
                        {
                            File.AppendAllText(codeWritingFailureFlagPath, $"\n\n--------------------\n");
                        }
                        Thread.Sleep(2500);
                        return 0;

                    case "set-installed":
                        if (args.Length < 2)
                        {
                            WriteToLog(logFilePath, "Error: Installation code required for set-installed");
                          //  Console.Error.WriteLine("Error: Installation code required.");
                            return 1;
                        }
                        string installedCode = args[1];
                        WriteToLog(logFilePath, $"Setting installation status to installed: {installedCode}");
                        bool setInstalledResult = await SetInstallationStatus(installedCode, "installed", logFilePath);
                        WriteToLog(logFilePath, $"Set installed result: {setInstalledResult}");
                        if (!setInstalledResult)
                        {
                            File.AppendAllText(codeStatusUpdateFailureFlagPath, $"\n\n--------------------\n");
                        }
                        Thread.Sleep(2500);
                        return setInstalledResult ? 0 : 1;

                    case "set-uninstalled":
                        if (args.Length < 2)
                        {
                            WriteToLog(logFilePath, "Error: Installation code required for set-uninstalled");
                          //  Console.Error.WriteLine("Error: Installation code required.");
                            return 1;
                        }
                        string uninstalledCode = args[1];
                        WriteToLog(logFilePath, $"Setting installation status to uninstalled: {uninstalledCode}");
                        ClearInstallationFiles(logFilePath);
                        bool setUninstalledResult = await SetInstallationStatus(uninstalledCode, "uninstalled", logFilePath);
                        WriteToLog(logFilePath, $"Set uninstalled result: {setUninstalledResult}");
                        return setUninstalledResult ? 0 : 1;

                    case "cleanup":
                        WriteToLog(logFilePath, $"Starting cleanup");
                        Cleanup(logFilePath, codeValidationFailureFlagPath, codeWritingFailureFlagPath, codeStatusUpdateFailureFlagPath);
                        
                        Thread.Sleep(1000);
                        return 0;
                    // New testing command to verify utility functionality
                    case "test":
                        WriteToLog(logFilePath, "Running self-test");
                       // Console.WriteLine("Installation Utility Test");
                        //Console.WriteLine("----------------------");

                        // Test log file
                       // Console.WriteLine($"Log file location: {logFilePath}");
                       // Console.WriteLine($"Can write to log: {CanWriteToPath(logFolderPath)}");

                        // Test registry access
                        bool canWriteToRegistry = false;
                        try
                        {
                            using (var testKey = Registry.LocalMachine.CreateSubKey(REGISTRY_DEBUG_PATH))
                            {
                                testKey.SetValue("TestValue", "Test " + DateTime.Now);
                                canWriteToRegistry = true;
                            }
                        }
                        catch { }
                       // Console.WriteLine($"Can write to registry: {canWriteToRegistry}");

                        // Test network access
                        bool canAccessNetwork = false;
                        try
                        {
                            using var httpClient = new HttpClient();
                            httpClient.Timeout = TimeSpan.FromSeconds(5);
                            var response = httpClient.GetAsync("https://www.google.com").GetAwaiter().GetResult();
                            canAccessNetwork = response.IsSuccessStatusCode;
                        }
                        catch { }
                       // Console.WriteLine($"Network access: {canAccessNetwork}");

                       // Console.WriteLine("Test complete!");
                        return 0;

                    default:
                        WriteToLog(logFilePath, $"Error: Unknown command '{command}'");
                      //  Console.Error.WriteLine($"Error: Unknown command '{command}'");
                        return 1;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(logFilePath, $"FATAL ERROR: {ex.GetType().Name}: {ex.Message}\nStack: {ex.StackTrace}");
               // Console.Error.WriteLine($"Error: {ex.Message}");

                // Also try to write to registry in case log file fails
                try
                {
                    using (var debugKey = Registry.LocalMachine.CreateSubKey(REGISTRY_DEBUG_PATH))
                    {
                        debugKey.SetValue("LastError", $"{ex.GetType().Name}: {ex.Message}");
                        debugKey.SetValue("ErrorStack", ex.StackTrace ?? "No stack trace");
                        debugKey.SetValue("ErrorTime", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                    }
                }
                catch
                {
                    // Nothing we can do if we can't log
                }

                return 1;
            }
            finally
            {
                WriteToLog(logFilePath, "Execution completed");
            }
        }

        private static void Cleanup(string logFilePath, string cvfPath, string cwfPath, string csufPath)
        {
            try
            {
                File.Delete(cvfPath);
                File.Delete(cwfPath);
                File.Delete(csufPath);
            }
            catch
            {
                
            }
        }

        private static void WriteToLog(string path, string message)
        {
            try
            {
                File.AppendAllText(path, $"[{DateTime.Now:HH:mm:ss.fff}] {message}\n");
            }
            catch
            {
                //// Silent failure - nothing we can do if we can't log
                //try
                //{
                //    // Try registry as backup
                //    using (var debugKey = Registry.LocalMachine.CreateSubKey(REGISTRY_DEBUG_PATH))
                //    {
                //        // Keep a log history in registry
                //        string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                //        for (int i = 4; i >= 1; i--)
                //        {
                //            object prevValue = debugKey.GetValue($"Log{i}");
                //            if (prevValue != null)
                //            {
                //                debugKey.SetValue($"Log{i + 1}", prevValue);
                //            }
                //        }
                //        debugKey.SetValue("Log1", $"[{timestamp}] {message}");
                //    }
                //}
                //catch
                //{
                //    // Really nothing we can do now
                //}
            }
        }

        private static bool CanWriteToPath(string path)
        {
            try
            {
                // Ensure directory exists
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }

                // Try to write a test file
                string testFile = Path.Combine(path, $"write_test_{Guid.NewGuid()}.tmp");
                File.WriteAllText(testFile, "Test");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<bool> ValidateInstallationCodeWithRetry(string installationCode, string logPath)
        {
            // Try up to 3 times with increasing delay
            for (int attempt = 1; attempt <= 1; attempt++)
            {
                try
                {
                    WriteToLog(logPath, $"Validation attempt {attempt}/3");
                    bool result = await ValidateInstallationCode(installationCode, logPath);
                    if (result)
                    {
                        return true;
                    }

                    // If we get here, the validation failed but didn't throw an exception
                    // Wait a bit before retrying
                    if (attempt < 3)
                    {
                        WriteToLog(logPath, $"Waiting {attempt} seconds before retry");
                        await Task.Delay(attempt * 1000);
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(logPath, $"Attempt {attempt} failed: {ex.Message}");
                    if (attempt < 3)
                    {
                        WriteToLog(logPath, $"Waiting {attempt} seconds before retry");
                        await Task.Delay(attempt * 1000);
                    }
                    else
                    {
                        // On final attempt, allow installation to proceed even on error
                        WriteToLog(logPath, "All retries failed, allowing installation to proceed anyway");
                        return false;
                    }
                }
            }

            // If we exhaust all retries without success or exception, 
            // allow installation to proceed in case of API issues
            WriteToLog(logPath, "Validation unsuccessful after all retries, allowing installation as fallback");
            return false;
        }

        private static async Task<bool> ValidateInstallationCode(string installationCode, string logPath)
        {
            try
            {
                WriteToLog(logPath, "Connecting to Firestore API...");

                using var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10); // Short timeout for installation process

                WriteToLog(logPath, $"Making API request to getInstallationCodeStatus");

                var response = await httpClient.GetAsync(
                    $"{API_BASE_URL}/getInstallationCodeStatus?installationCode={installationCode}");

                if (!response.IsSuccessStatusCode)
                {
                    var errorText = await response.Content.ReadAsStringAsync();
                    WriteToLog(logPath, $"Error fetching status: {response.StatusCode} - {errorText}");
                   // Console.WriteLine($"Error fetching status: {response.StatusCode} - {errorText}");
                    return false;
                }

                if (response == null)
                {
                    WriteToLog(logPath, "Failed to get response from API");
                  //  Console.WriteLine("Failed to get response from API");
                    return false;
                }

                WriteToLog(logPath, "Deserializing API response");
                var responseData = await response.Content.ReadFromJsonAsync<InstallationCodeStatus>();

                if (responseData == null)
                {
                    WriteToLog(logPath, "Invalid or empty response data");
                   // Console.WriteLine("Invalid or empty response data");
                    return false;
                }

                WriteToLog(logPath, $"Installation code status: {responseData.status}");
               // Console.WriteLine($"Installation code status: {responseData.status}");

                return responseData.status == "pending" || responseData.status == "uninstalled";
            }
            catch (Exception ex)
            {
                WriteToLog(logPath, $"Validation error: {ex.GetType().Name}: {ex.Message}");
              //  Console.WriteLine($"Validation error: {ex.Message}");
                // During development, return true to allow installation even if API is unavailable
                WriteToLog(logPath, "DEBUG MODE: Allowing installation despite validation error");
               // Console.WriteLine("DEBUG MODE: Allowing installation despite validation error");
                return true;
            }
        }

        private static bool WriteInstallationCode(string installationCode, string installPath, string logPath)
        {
            bool result = false;
            // Write to registry
            try
            {
                WriteToLog(logPath, "Writing to registry...");
                using (var key = Registry.LocalMachine.CreateSubKey(REGISTRY_KEY_PATH))
                {
                    key.SetValue(REGISTRY_VALUE_NAME, installationCode);
                }
                WriteToLog(logPath, "Registry write complete");
                result = true;
            }
            catch (Exception ex)
            {
                WriteToLog(logPath, $"Registry write error: {ex.GetType().Name}: {ex.Message}");
               // Console.WriteLine($"Registry write error: {ex.Message}");
            }

            // Write to encrypted file
            try
            {
                if (!string.IsNullOrEmpty(installPath))
                {
                    WriteToLog(logPath, $"Writing encrypted file to {installPath}");
                    var encryptedData = EncryptString(installationCode);
                    File.WriteAllBytes(Path.Combine(installPath, ENCRYPTED_FILE_NAME), encryptedData);
                    WriteToLog(logPath, "File write complete");
                }
                result = true;
            }
            catch (Exception ex)
            {
                WriteToLog(logPath, $"File write error: {ex.GetType().Name}: {ex.Message}");
               // Console.WriteLine($"File write error: {ex.Message}");
            }
            return result;
        }

        private static async Task<bool> ClearInstallationFiles( string logPath)
        {
            WriteToLog(logPath, $"Cleaning files");

            string serviceName = "RmmMonitorService";
            try
            {
                using (ServiceController sc = new ServiceController(serviceName))
                {
                    if (sc.Status != ServiceControllerStatus.Stopped)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                    }
                }

                // Remove service
                Process.Start(new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"delete {serviceName}",
                    Verb = "runas",
                    CreateNoWindow = true,
                    UseShellExecute = false
                })?.WaitForExit();
            }
            catch (InvalidOperationException ex)
            {
                WriteToLog(logPath, $"Stopping service error: {ex.GetType().Name}: {ex.Message}");
            }
            catch (Exception ex)
            {
                WriteToLog(logPath, $"Stopping service error: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                string installPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "MyApp");
                if (Directory.Exists(installPath))
                {
                    Directory.Delete(installPath, recursive: true);
                }
            }
            catch (Exception ex)
            {
                WriteToLog(logPath, $"Stopping service error: {ex.GetType().Name}: {ex.Message}");
            }

            return true;
        }


        private static async Task<bool> SetInstallationStatus(string installationCode, string status, string logPath)
        {
            try
            {
                WriteToLog(logPath, $"Setting installation status to {status}...");

                // For testing purposes
                if (Environment.GetEnvironmentVariable("SKIP_API_VALIDATION") == "1")
                {
                    WriteToLog(logPath, "API update skipped (TEST MODE)");
                   // Console.WriteLine("API update skipped (TEST MODE)");
                    return true;
                }

                var payload = new InstallationCodeStatus
                {
                    status = status,
                    installationCode = installationCode
                };

                WriteToLog(logPath, $"Making API request to updateInstallationCodeStatus");
                var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    TypeInfoResolver = AppJsonSerializerContext.Default
                };


                using var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10);

                var response = await httpClient.PutAsJsonAsync(
                    $"{API_BASE_URL}/updateInstallationCodeStatus", payload, options);

                if (!response.IsSuccessStatusCode)
                {
                    var errorText = await response.Content.ReadAsStringAsync();
                    WriteToLog(logPath, $"Error updating status: {response.StatusCode} - {errorText}");
                   // Console.WriteLine($"Error updating status: {response.StatusCode} - {errorText}");
                }

                if (response.IsSuccessStatusCode)
                {
                    WriteToLog(logPath, "Status updated successfully");
                   // Console.WriteLine("Status updated successfully");
                    return true;
                }
                else
                {
                    WriteToLog(logPath, $"Failed to update status: {response.StatusCode}");
                   // Console.WriteLine($"Failed to update status: {response.StatusCode}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(logPath, $"Status update error: {ex.GetType().Name}: {ex.Message}");
              //  Console.WriteLine($"Status update error: {ex.Message}");
                // During development, return true to allow process to continue
                WriteToLog(logPath, "DEBUG MODE: Continuing despite update error");
                //Console.WriteLine("DEBUG MODE: Continuing despite update error");
                return true;
            }
        }

        private static byte[] EncryptString(string plainText)
        {
            try
            {
                byte[] key = new byte[32]; // 256 bit key
                byte[] iv = new byte[16];  // 128 bit IV

                // In a real implementation, you would use a proper key derivation
                // This is just for demonstration purposes
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                    rng.GetBytes(iv);
                }

                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;

                using var encryptor = aes.CreateEncryptor();
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                // Format: [16 bytes IV][32 bytes key][cipher text]
                byte[] result = new byte[iv.Length + key.Length + cipherBytes.Length];
                Array.Copy(iv, 0, result, 0, iv.Length);
                Array.Copy(key, 0, result, iv.Length, key.Length);
                Array.Copy(cipherBytes, 0, result, iv.Length + key.Length, cipherBytes.Length);

                return result;
            }
            catch (Exception ex)
            {
                // In case of encryption failure, store plain text
                return Encoding.UTF8.GetBytes("UNENCRYPTED:" + plainText);
            }
        }
    }
}