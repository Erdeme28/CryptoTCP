using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Server
{
    public enum MessageType { DH_PubKey, Chat }

    public class SecurePacket
    {
        public MessageType Type { get; set; }
        public string PublicKey { get; set; } = string.Empty;
        public string IVBase64 { get; set; } = string.Empty;
        public string CiphertextBase64 { get; set; } = string.Empty;
        public string HashBase64 { get; set; } = string.Empty;
    }

    class Program
    {
        static readonly BigInteger p = 23;
        static readonly BigInteger g = 5;
        static readonly BigInteger serverPrivateKey = 3;

        static byte[]? sharedAesKey;

        static async Task Main()
        {
            Console.WriteLine("=========================================");
            Console.WriteLine("   SECURE SERVER (TCP | DH + AES + SHA256) ");
            Console.WriteLine("=========================================\n");

            TcpListener listener = new TcpListener(IPAddress.Any, 11000);
            listener.Start();
            Console.WriteLine("Listening on port 11000...");

            using TcpClient client = await listener.AcceptTcpClientAsync();
            Console.WriteLine("[!] Client connected!\n");

            using NetworkStream stream = client.GetStream();
            using StreamReader reader = new StreamReader(stream, Encoding.UTF8);
            using StreamWriter writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

            BigInteger B = BigInteger.ModPow(g, serverPrivateKey, p);

            string? clientMsg = await reader.ReadLineAsync();
            SecurePacket dhPacketRx = JsonSerializer.Deserialize<SecurePacket>(clientMsg!)!;
            BigInteger A = BigInteger.Parse(dhPacketRx.PublicKey);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"    <- [RX] Client Public Key (A) received: {A}");

            SecurePacket dhPacketTx = new SecurePacket { Type = MessageType.DH_PubKey, PublicKey = B.ToString() };
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[TX] Sending Server Public Key (B): {B}");
            Console.ResetColor();
            await writer.WriteLineAsync(JsonSerializer.Serialize(dhPacketTx));

            BigInteger S = BigInteger.ModPow(A, serverPrivateKey, p);
            sharedAesKey = SHA256.HashData(Encoding.UTF8.GetBytes(S.ToString()));

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[KEY] Shared Secret (S) established: {S}");
            Console.WriteLine("--- SECURE CHAT STARTED ---\n");
            Console.ResetColor();

            _ = Task.Run(() => ReceiveMessages(reader));

            while (true)
            {
                string input = Console.ReadLine() ?? "";
                if (string.IsNullOrWhiteSpace(input)) continue;

                SecurePacket pkt = EncryptMessage(input);

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"[TX Ciphertext]: {pkt.CiphertextBase64}");
                Console.ResetColor();

                await writer.WriteLineAsync(JsonSerializer.Serialize(pkt));
            }
        }

        static async Task ReceiveMessages(StreamReader reader)
        {
            try
            {
                while (true)
                {
                    string? json = await reader.ReadLineAsync();
                    if (json == null) break;

                    SecurePacket pkt = JsonSerializer.Deserialize<SecurePacket>(json)!;

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"\n    <- [RX Ciphertext]: {pkt.CiphertextBase64}");

                    bool isIntact = VerifyIntegrity(pkt);
                    if (!isIntact)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("    [!] INTEGRITY ERROR: Hash mismatch! Packet rejected.");
                        Console.ResetColor();
                        continue;
                    }

                    string decrypted = DecryptMessage(pkt);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"    <- [RX Decrypted]: {decrypted}");
                    Console.ResetColor();
                }
            }
            catch (Exception) { Console.WriteLine("Connection lost."); }
        }

        static SecurePacket EncryptMessage(string plainText)
        {
            using Aes aes = Aes.Create();
            aes.Key = sharedAesKey!;
            aes.GenerateIV();

            byte[] cipherBytes;
            using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                }
                cipherBytes = ms.ToArray();
            }

            string cipherBase64 = Convert.ToBase64String(cipherBytes);
            string hashBase64 = Convert.ToBase64String(SHA256.HashData(cipherBytes));

            return new SecurePacket
            {
                Type = MessageType.Chat,
                IVBase64 = Convert.ToBase64String(aes.IV),
                CiphertextBase64 = cipherBase64,
                HashBase64 = hashBase64
            };
        }

        static string DecryptMessage(SecurePacket pkt)
        {
            using Aes aes = Aes.Create();
            aes.Key = sharedAesKey!;
            aes.IV = Convert.FromBase64String(pkt.IVBase64);
            byte[] cipherBytes = Convert.FromBase64String(pkt.CiphertextBase64);

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (MemoryStream ms = new MemoryStream(cipherBytes))
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }

        static bool VerifyIntegrity(SecurePacket pkt)
        {
            byte[] cipherBytes = Convert.FromBase64String(pkt.CiphertextBase64);
            string calculatedHash = Convert.ToBase64String(SHA256.HashData(cipherBytes));
            return calculatedHash == pkt.HashBase64;
        }
    }
}