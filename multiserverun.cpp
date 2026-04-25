#include <iostream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <algorithm>

const int REQUIRED_CLIENTS = 3;

std::mutex              session_mtx;
std::condition_variable session_cv;
std::vector<std::vector<double>> stored_vecs;
std::vector<int>        waiting_sockets;
std::string             result_bytes;
bool                    result_ready = false;

// ── net helpers ───────────────────────────────────────────────────────────────

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

// Serialize a vector<double> as: [uint32 count][double0][double1]...
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

// ── per-client handler ────────────────────────────────────────────────────────

void handle_client(int sock) {
    std::cout << "Client connected: fd=" << sock << "\n";

    std::string mode = recv_blob(sock);

    if (mode == "SUBMIT") {
        std::string blob = recv_blob(sock);
        if (blob.empty()) { close(sock); return; }

        std::vector<double> vec = deserialize_vec(blob);

        {
            std::unique_lock<std::mutex> lk(session_mtx);

            stored_vecs.push_back(vec);
            waiting_sockets.push_back(sock);

            std::cout << "Received vec " << stored_vecs.size()
                      << "/" << REQUIRED_CLIENTS << ": [";
            for (size_t i = 0; i < vec.size(); i++)
                std::cout << vec[i] << (i + 1 < vec.size() ? ", " : "");
            std::cout << "]\n";

            if ((int)stored_vecs.size() == REQUIRED_CLIENTS) {
                std::cout << "All clients ready — computing sum...\n";

                // element-wise sum
                size_t len = stored_vecs[0].size();
                std::vector<double> sum(len, 0.0);
                for (auto& v : stored_vecs)
                    for (size_t i = 0; i < len; i++)
                        sum[i] += v[i];

                std::cout << "Sum: [";
                for (size_t i = 0; i < sum.size(); i++)
                    std::cout << sum[i] << (i + 1 < sum.size() ? ", " : "");
                std::cout << "]\n";

                result_bytes = serialize_vec(sum);
                result_ready = true;
                session_cv.notify_all();
            } else {
                session_cv.wait(lk, [] { return result_ready; });
            }
        }

        if (!send_blob(sock, result_bytes))
            std::cerr << "Failed to send result to fd=" << sock << "\n";
        else
            std::cout << "Result sent to fd=" << sock << "\n";

        close(sock);

        {
            std::lock_guard<std::mutex> lk(session_mtx);
            waiting_sockets.erase(
                std::remove(waiting_sockets.begin(), waiting_sockets.end(), sock),
                waiting_sockets.end());

            if (waiting_sockets.empty()) {
                stored_vecs.clear();
                result_bytes.clear();
                result_ready = false;
                std::cout << "Session reset — ready for next batch\n";
            }
        }
        return;
    }

    send_blob(sock, "UNKNOWN_COMMAND");
    close(sock);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    const int PORT = 4040;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 100) < 0) { perror("listen"); return 1; }

    std::cout << "Listening on port " << PORT
              << " — waiting for " << REQUIRED_CLIENTS << " clients\n";

    while (true) {
        int sock = accept(server_fd, nullptr, nullptr);
        if (sock < 0) { std::cerr << "accept failed\n"; continue; }
        std::thread(handle_client, sock).detach();
    }

    close(server_fd);
}