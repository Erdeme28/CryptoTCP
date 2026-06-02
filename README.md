# Secure TCP Chat (Diffie-Hellman + AES-256 + SHA-256)

A custom secure client-server messaging application built in C#. This project demonstrates the practical implementation of cryptographic primitives to establish a secure, end-to-end encrypted communication channel over standard TCP sockets.

## Cryptographic Architecture

This application implements a custom secure handshake and message exchange protocol:

1. **Key Exchange (Diffie-Hellman):**
   - The Client and Server dynamically generate a shared secret over an insecure TCP channel using the Diffie-Hellman mathematical algorithm (BigInteger.ModPow).
   - The shared secret is never transmitted across the network.
   
2. **Key Derivation:**
   - The raw Diffie-Hellman shared secret is hashed using SHA-256 to derive a robust 256-bit symmetric key for AES.

3. **Confidentiality (AES Encryption):**
   - All chat messages are encrypted using the Advanced Encryption Standard (AES) before transmission.
   - A unique Initialization Vector (IV) is generated for every single message to prevent cryptographic pattern analysis.

4. **Integrity (SHA-256):**
   - To prevent packet tampering or Man-in-the-Middle (MITM) manipulations, each packet includes a SHA-256 hash of the ciphertext. 
   - The receiver recalculates the hash upon arrival and drops the packet immediately if an integrity mismatch is detected.

## Technical Details

- **Language & Framework:** C# / .NET
- **Networking:** Asynchronous TCP Sockets (TcpListener, TcpClient, NetworkStream).
- **Data Serialization:** Packets are structured via a SecurePacket class and serialized to JSON. Binary cryptographic data (Ciphertext, IV, Hashes) is Base64 encoded for safe network transport.

## How It Works (Console Flow)

When running the Client and Server, the console outputs a color-coded trace of the cryptographic process:
* **[TX/RX]** - Shows the exchange of Public Keys (A and B).
* **[KEY]** - Confirms the successful generation of the Shared Secret (S).
* **[Ciphertext]** - Displays the actual encrypted Base64 string sent over the wire.
* **[Decrypted]** - Displays the final plaintext message after successful integrity checks and AES decryption.

> **Note on Cryptographic Parameters:** For demonstration and console debugging purposes, this implementation uses small prime numbers (p = 23, g = 5) for the Diffie-Hellman key exchange. In a production environment, these would be replaced by 2048-bit or 4096-bit safe primes (RFC 3526) or Elliptic Curve variants (ECDH).
