#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>
#include <random>
#include <map>

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

std::map<std::string, std::string> parse_args(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc - 1; i += 2)
        args[argv[i]] = argv[i + 1];
    return args;
}

int connect_to_server(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return -1;
    }
    return sock;
}

int main(int argc, char* argv[]) {
    auto args = parse_args(argc, argv);

    int         vec_size   = args.count("--vec_size")   ? std::stoi(args["--vec_size"])   : 8;
    std::string value_type = args.count("--value_type") ? args["--value_type"]             : "CONST";
    double      const_val  = args.count("--value")      ? std::stod(args["--value"])       : 1.0;
    int         seed       = args.count("--seed")       ? std::stoi(args["--seed"])        : 42;
    std::string mode       = args.count("--mode")       ? args["--mode"]                   : "submit";
    std::string server_ip  = args.count("--server_ip")  ? args["--server_ip"]              : "127.0.0.1";
    int         port       = args.count("--port")       ? std::stoi(args["--port"])        : 4040;
    int         repeat     = args.count("--repeat")     ? std::stoi(args["--repeat"])      : 1;

    std::mt19937 gen(seed);
    std::uniform_real_distribution<> dist(0.0, 10.0);

    double total_time = 0;

    for (int r = 0; r < repeat; r++) {

        std::vector<double> data(vec_size);
        for (int i = 0; i < vec_size; i++)
            data[i] = (value_type == "RANDOM") ? dist(gen) : const_val;

        std::string payload = serialize_vec(data);
        size_t payload_size = payload.size();

        auto start = std::chrono::high_resolution_clock::now();

        int sock = connect_to_server(server_ip, port);
        if (sock < 0) { std::cerr << "Connection failed on repeat " << r << "\n"; continue; }

        send_blob(sock, "SUBMIT");
        if (!send_blob(sock, payload)) {
            std::cerr << "Failed to send data on repeat " << r << "\n";
            close(sock); continue;
        }

        std::string res_blob = recv_blob(sock);
        close(sock);

        auto end = std::chrono::high_resolution_clock::now();

        if (res_blob.empty()) { std::cerr << "Empty result on repeat " << r << "\n"; continue; }

        double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        total_time += total_ms;

        // plaintext has no encrypt step so encrypt_ms=0, ciphertext_bytes=payload size
        std::cout << "vector_size=" << vec_size
                  << ",mode=" << mode
                  << ",encrypt_ms=0"
                  << ",total_ms=" << total_ms
                  << ",ciphertext_bytes=" << payload_size
                  << "\n";
    }

    std::cout << "avg_total_ms=" << (total_time / repeat) << "\n";
    return 0;
}