#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>

bool send_all(int sock, const void* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t s = send(sock, (const char*)buf + sent, len - sent, 0);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

bool recv_all(int sock, void* buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t r = recv(sock, (char*)buf + received, len - received, 0);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

int main() {
    std::vector<int32_t> data = {1, 2, 3, 4};
    for(int32_t i = 5; i < 1000; i++){
        data.push_back(i);
    }
    

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4040);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

    std::cout << "Connected to server\n";

    auto start = std::chrono::steady_clock::now();

    // send size
    uint32_t size = htonl(data.size());
    send_all(sock, &size, sizeof(size));

    // send raw data
    send_all(sock, data.data(), data.size() * sizeof(int32_t));

    // receive result size
    uint32_t res_size;
    recv_all(sock, &res_size, sizeof(res_size));
    res_size = ntohl(res_size);

    std::vector<int32_t> result(res_size);

    // receive result data
    recv_all(sock, result.data(), res_size * sizeof(int32_t));

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    std::cout << "Elapsed time: " << elapsed.count() << "s\n";

    // std::cout << "Result: [";
    // for (size_t i = 0; i < result.size(); i++) {
    //     std::cout << result[i];
    //     if (i + 1 < result.size()) std::cout << ", ";
    // }
    // std::cout << "]\n";

    close(sock);
}
