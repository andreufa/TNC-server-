Command number 0x65 - Device Authorization (hereinafter referred to as AT) on the server
The server authorization algorithm is as follows:
1. The AT sends a Parameter Request (address/specifier 0x61) to the server, specifying
its own Device ID (DID);

Preamble Address | Specifier Number Length Data CRC
0x24 0x61 0x65 0x000A 14 bytes 1 byte

Data Type:
Device ID (DID) 14 bytes 

2. The server responds to the Parameter Request (address/specifier 0x64) specifying
the current server Timestamp and nonce (challenge);

Preamble Address | Specifier Number Length Status Data CRC
0x24 0x64 0x65 0x0029 1 byte 40 bytes 1 byte

Data                    Type 
nonce (challenge)       32-byte sequence
Current server time UTC  8 bytes uint64 milliseconds       Unix-time*1000

3. The AT generates an RSA signature based on these values ​​and sends an authorization command (address/specifier 0x60) specifying its own device ID (DID) and the RSA signature;

Preamble Address + Specifier Number Length Data CRC
0x24 0x60 0x65 0x010F 271 bytes 1 byte
Data type:
Data type Size
Device ID 14 bytes
Authentication protocol version 1 byte
RSA signature 256 bytes uint8

4. The server sends two standard responses to the command (address/specifier 0x63)

First response
Preamble Address | Specifier Number Length Status CRC
0x24 0x63 0x65 0x0001 0x00 1 byte

Second response
Preamble Address | Specifier Number Length Status CRC
0x24 0x63 0x65 0x0001 0x01 if authorization is successful and 0x06 if not 1 byte

This is the processing of command 0x65 and all its messages and requests. There will be many such commands. Therefore, it makes sense to separate the general methods into a file like frame.go and put the specific methods for processing specific commands into packages like
internal/cmd/cmd0x65 (as an example for command 0x65)

Then we already have commands 0x65 and 0x59 (regular messages).

Let's configure the server to work with this protocol.



The client will send a regular message
Preamble Address + Specifier Number Length Data CRC
0x24 0x76 0x59 0x002C 44 bytes 1 byte
The server's task upon receiving such a message is to change the Address + Specifier to 0x70 and send a broadcast message.

Add functionality to the client so that it sends a regular message to the Server once per second.
Add the required functionality to the Server.

Let the data for the regular message be like this
24 76 59 2C 00 46 23 00 00 F0 AA 4A 60 9F 01 00 00 00 00 00 00 00 00 00 00 73 6F 63 9A 19 E8 A1 40 0A DD 6E 28 5D BA A5 C0 B9 00 00 00 07 00 00 00 F4