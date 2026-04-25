#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>

const std::string SERVER_IP = "127.0.0.1";
const int         PORT      = 4040;

bool recv_all(int sock, void* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(sock, (char*)buf + got, len - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool send_all(int sock, const void* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t s = send(sock, (const char*)buf + sent, len - sent, 0);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

bool send_blob(int sock, const std::string& data) {
    uint32_t len = htonl(data.size());
    return send_all(sock, &len, 4) && send_all(sock, data.data(), data.size());
}

std::string recv_blob(int sock) {
    uint32_t len = 0;
    if (!recv_all(sock, &len, 4)) return "";
    len = ntohl(len);
    std::string buf(len, '\0');
    return recv_all(sock, buf.data(), len) ? buf : "";
}

std::string serialize_vec(const std::vector<double>& v) {
    std::string out;
    uint32_t n = htonl(v.size());
    out.append((char*)&n, 4);
    for (double d : v)
        out.append((char*)&d, sizeof(double));
    return out;
}

std::vector<double> deserialize_vec(const std::string& blob) {
    if (blob.size() < 4) return {};
    uint32_t n;
    memcpy(&n, blob.data(), 4);
    n = ntohl(n);
    std::vector<double> v(n);
    for (uint32_t i = 0; i < n; i++)
        memcpy(&v[i], blob.data() + 4 + i * sizeof(double), sizeof(double));
    return v;
}

int connect_to_server() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, SERVER_IP.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return -1;
    }
    return sock;
}

int main() {
    std::vector<double> data = {1.1, 2.2, 3.3, 4.4, 5.0, 6.0, 7.0, 8.0};

    auto start = std::chrono::steady_clock::now();

    // single connection — send data, block until sum arrives
    int sock = connect_to_server();
    if (sock < 0) return 1;
    std::cout << "Connected\n";

    send_blob(sock, "SUBMIT");
    if (!send_blob(sock, serialize_vec(data))) {
        std::cerr << "Failed to send data\n"; return 1;
    }
    std::cout << "Sent — waiting for all clients...\n";

    std::string res_blob = recv_blob(sock);
    close(sock);
    if (res_blob.empty()) { std::cerr << "Failed to receive result\n"; return 1; }

    std::vector<double> result = deserialize_vec(res_blob);

    std::cout << "Sum: [";
    for (size_t i = 0; i < result.size(); i++)
        std::cout << result[i] << (i + 1 < result.size() ? ", " : "");
    std::cout << "]\n";

    auto end = std::chrono::steady_clock::now();
    std::cout << "Elapsed: "
              << std::chrono::duration<double>(end - start).count() << "s\n";

    return 0;
}