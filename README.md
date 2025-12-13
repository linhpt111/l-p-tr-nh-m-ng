# CChatApp

Multi-client chat application in C with GTK GUI, RSA/AES crypto, 1-1 and group chat. Server acts as broker.
Multiclient chat app in C with a GTK GUI. Supports broadcast, 1:1 direct messages, group chat, RSA key exchange, and AES-256-CBC encryption. The server acts as a broker.

## Features
- Multi-threaded server, multiple clients.
- Multi-threaded server, multiple simultaneous clients.
- Broadcast, direct messages, group chat (create/join).
- RSA key exchange, AES-256-CBC for content.
- GTK client: enter IP/port/username, send/receive, select user/group.
- RSA for key exchange, AES-256-CBC for message/content encryption.
- GTK client: enter IP/port/username, send/receive, select user or group.

## Requirements
- OpenSSL, SQLite3, GTK+3, pkg-config, C toolchain.
- Run from project root so relative paths (gui/*.glade, keys, db) resolve correctly.
## Prerequisites
- OpenSSL, SQLite3, GTK+3, pkg-config, and a C toolchain.
- Run from the project root so relative paths (`gui/*.glade`, keys, DB) resolve correctly.

## Build & run on Windows (MSYS2/MinGW)
1. Install toolchain/libs (MSYS2 MinGW64 shell):
   ```
1. Install toolchain and libs (MSYS2 MinGW64 shell):
   ```bash
   pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-pkg-config \
     mingw-w64-x86_64-gtk3 mingw-w64-x86_64-openssl mingw-w64-x86_64-sqlite3
   ```
2. Build:
   ```
   ```bash
   cd /c/Users/phamt/Desktop/ltm/CChatApp
   mingw32-make        # builds bin/server.exe and bin/client.exe
   mingw32-make              # builds bin/server.exe and bin/client.exe
   ```
3. Run:
   ```
   ./bin/server.exe    # IP 0.0.0.0 and port (e.g., 8080)
   ./bin/client.exe    # IP of server (from ipconfig) and same port
   ```
4. Windows firewall: allow the TCP port (e.g., 8080) for inbound connections.
5. If you will also build on Linux/WSL and want to keep the .exe files, rename them first to avoid overwrite:
   ```bash
   ./bin/server.exe          # use IP 0.0.0.0 and a port (e.g., 8080)
   ./bin/client.exe          # IP of server (from ipconfig) and same port
   ```
4. Allow the TCP port (e.g., 8080) through Windows Firewall.
5. If you also build on Linux/WSL and want to keep the .exe files, rename them first:
   ```bash
   mv bin/server.exe bin/server_win.exe
   mv bin/client.exe bin/client_win.exe
   ```

## Build & run on Linux (including WSL)
1. Install deps (Ubuntu/Debian):
   ```
   ```bash
   sudo apt update
   sudo apt install -y build-essential pkg-config libgtk-3-dev libssl-dev libsqlite3-dev
   ```
2. Build (clean old Linux artefacts; keep renamed *.exe if needed):
   ```
   ```bash
   cd /path/to/CChatApp          # or /mnt/c/... when in WSL
   rm -rf build bin/server bin/client
   make                          # builds bin/server and bin/client for Linux
   ```
3. Run:
   ```
   ```bash
   ./bin/server
   ./bin/client
   ```
   Note: if server is on Windows, client must use the Windows host LAN IP (not localhost).
   If the server is on Windows, the client must use the Windows host LAN IP (not localhost).

## Protocol (summary)
- Framing: 4-byte length (htonl/ntohl) + IV 16 bytes + AES-256-CBC ciphertext.
- PacketHeader (packed):
  - msgType: MSG_LOGIN/LOGOUT/SUBSCRIBE/UNSUBSCRIBE/PUBLISH_TEXT/PUBLISH_FILE/FILE_DATA/ERROR/ACK
  - payloadLength, messageId, timestamp, version, flags, sender, topic, checksum.
- Framing: 4-byte length (htonl/ntohl) + 16-byte IV + AES-256-CBC ciphertext.
- `PacketHeader` (packed):
  - `msgType`: MSG_LOGIN / LOGOUT / SUBSCRIBE / UNSUBSCRIBE / PUBLISH_TEXT / PUBLISH_FILE / FILE_DATA / ERROR / ACK
  - `payloadLength`, `messageId`, `timestamp`, `version`, `flags`, `sender`, `topic`, `checksum`.
- Channels:
  - Broadcast: topic = "ALL", flags = 0.
  - DM: topic = username, flags = 0.
  - Group: topic = group name, flags bit0 = 1.
- Groups: send MSG_SUBSCRIBE to topic; flags=1 to CREATE, flags=0 to JOIN. Server stores membership in DB.
- Presence/group lists: server replies via MSG_ACK (topic="PRESENCE"/"GROUPS", payload CSV).
- Messages: MSG_PUBLISH_TEXT, payload is plaintext; header carries sender/topic for routing.
  - Broadcast: `topic = "ALL"`, `flags = 0`.
  - Direct: `topic = <username>`, `flags = 0`.
  - Group: `topic = <group name>`, `flags bit0 = 1`.
- Groups: send `MSG_SUBSCRIBE` to the group topic; `flags = 1` to CREATE, `flags = 0` to JOIN. Server stores membership in the DB.
- Presence/groups: server replies via `MSG_ACK` (`topic = "PRESENCE"` / `"GROUPS"`, payload CSV).
- Messages: `MSG_PUBLISH_TEXT`, payload is plaintext; header carries sender/topic for routing.

## Assets/paths
- GUI: `gui/*.glade`
## Paths
- GUI files: `gui/*.glade`
- Keys: `socket_server/server_private.pem`, `socket_server/server_public.pem`
- Database: `chat_app.db`

## License
MIT (see LICENSE).
MIT (see `LICENSE`).