# CChatApp

Ứng dụng chat đa máy viết bằng C, hỗ trợ GUI GTK, mã hóa RSA/AES, chat 1-1 và chat nhóm.

## Chức năng hiện có
- Server đa luồng, nhiều client kết nối đồng thời.
- Chat broadcast (mọi người), chat 1-1 (DM), chat nhóm (tạo/join nhóm).
- Mã hóa: trao đổi khóa RSA, dùng AES cho nội dung.
- Giao diện GTK (client): nhập IP/PORT/username, gửi/nhận tin, chọn người/nhóm.

## Yêu cầu chung
- OpenSSL, SQLite3, GTK+3, pkg-config, trình biên dịch C.
- Chạy từ thư mục gốc dự án; code tự đưa CWD về gốc nên có thể chạy từ bất kỳ nơi nào.

## Build & chạy trên Windows (MSYS2/MinGW)
1. Cài gói (MSYS2):
   ```
   pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-pkg-config \
     mingw-w64-x86_64-gtk3 mingw-w64-x86_64-openssl mingw-w64-x86_64-sqlite3
   ```
2. Mở terminal MinGW64, vào thư mục dự án:
   ```
   cd /c/Users/phamt/Desktop/ltm/CChatApp
   mingw32-make        # build server + client
   ```
3. Chạy server:
   ```
   ./bin/server.exe    # nhập IP 0.0.0.0 (mọi giao diện) và PORT, ví dụ 8080
   ```
4. Chạy client Windows:
   ```
   ./bin/client.exe    # nhập IP máy server (IPv4 từ ipconfig) và PORT
   ```
5. Mở firewall Windows cho cổng TCP bạn dùng (ví dụ 8080) để client khác máy kết nối.

## Build & chạy trên Linux
1. Cài gói (Ubuntu/Debian):
   ```
   sudo apt update
   sudo apt install build-essential pkg-config libgtk-3-dev libssl-dev libsqlite3-dev
   ```
2. Vào thư mục dự án:
   ```
   cd /path/to/CChatApp            # hoặc /mnt/c/... nếu dùng WSL
   make            # build server + client (tạo bin/server, bin/client)
   ```
3. Chạy client Linux:
   ```
   ./bin/client    # nhập IP máy Windows và PORT (ví dụ 8080)
   ```
   Lưu ý: client Linux phải trỏ IP thật của máy Windows (LAN), không dùng localhost khi server ở Windows.

## Lưu ý vận hành
- Đảm bảo server listen trên 0.0.0.0 để client khác máy truy cập.
- Đảm bảo firewall/router không chặn cổng.
- Các file tài nguyên: `gui/*.glade`, `chat_app.db`, `socket_server/server_private.pem`, `socket_server/server_public.pem` được tìm theo thư mục gốc dự án.

## Giấy phép
MIT License (xem [LICENSE](LICENSE)).
