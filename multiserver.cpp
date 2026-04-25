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

#include "openfhe.h"
#include <cryptocontext-ser.h>
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"

using namespace lbcrypto;

const int REQUIRED_CLIENTS = 3;

CryptoContext<DCRTPoly> cc;
KeyPair<DCRTPoly>        keyPair;

std::mutex              session_mtx;
std::condition_variable session_cv;
std::vector<Ciphertext<DCRTPoly>> stored_cts;
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

// ── per-client handler ────────────────────────────────────────────────────────

void handle_client(int sock) {
    std::cout << "Client connected: fd=" << sock << "\n";

    std::string mode = recv_blob(sock);

    // ── key distribution ──────────────────────────────────────────────────────
    if (mode == "GET_PUBKEY") {
        std::stringstream ss;
        Serial::Serialize(keyPair.publicKey, ss, SerType::BINARY);
        send_blob(sock, ss.str());
        close(sock);
        return;
    }

    if (mode == "GET_EVALKEY") {
        std::stringstream ss;
        cc->SerializeEvalMultKey(ss, SerType::BINARY);
        send_blob(sock, ss.str());
        close(sock);
        return;
    }

    if (mode == "GET_CONTEXT") {
        std::stringstream ss;
        Serial::Serialize(cc, ss, SerType::BINARY);
        send_blob(sock, ss.str());
        close(sock);
        return;
    }

    if (mode == "GET_SECRETKEY") {
        std::stringstream ss;
        Serial::Serialize(keyPair.secretKey, ss, SerType::BINARY);
        send_blob(sock, ss.str());
        close(sock);
        return;
    }

    // ── ciphertext submission and barrier ─────────────────────────────────────
    if (mode == "SUBMIT") {
        std::string ct_bytes = recv_blob(sock);
        if (ct_bytes.empty()) { close(sock); return; }

        Ciphertext<DCRTPoly> ct;
        { std::stringstream ss(ct_bytes); Serial::Deserialize(ct, ss, SerType::BINARY); }

        {
            std::unique_lock<std::mutex> lk(session_mtx);

            stored_cts.push_back(ct);
            waiting_sockets.push_back(sock);

            std::cout << "Received ct " << stored_cts.size()
                      << "/" << REQUIRED_CLIENTS << "\n";

            if ((int)stored_cts.size() == REQUIRED_CLIENTS) {
                // last client — compute the sum
                std::cout << "All clients ready — computing sum...\n";

                Ciphertext<DCRTPoly> sum = stored_cts[0];
                for (int i = 1; i < REQUIRED_CLIENTS; ++i)
                    sum = cc->EvalAdd(sum, stored_cts[i]);

                std::stringstream rs;
                Serial::Serialize(sum, rs, SerType::BINARY);
                result_bytes = rs.str();
                result_ready = true;

                session_cv.notify_all();
            } else {
                // wait for remaining clients
                session_cv.wait(lk, [] { return result_ready; });
            }
        }

        // send result back to this client
        if (!send_blob(sock, result_bytes))
            std::cerr << "Failed to send result to fd=" << sock << "\n";
        else
            std::cout << "Result sent to fd=" << sock << "\n";

        close(sock);

        // reset session once all sockets are done
        {
            std::lock_guard<std::mutex> lk(session_mtx);
            waiting_sockets.erase(
                std::remove(waiting_sockets.begin(), waiting_sockets.end(), sock),
                waiting_sockets.end());

            if (waiting_sockets.empty()) {
                stored_cts.clear();
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

    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(3);
    params.SetScalingModSize(50);
    params.SetBatchSize(8);

    cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Keys generated. Listening on port " << PORT << "\n";

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 100) < 0) { perror("listen"); return 1; }

    std::cout << "Waiting for " << REQUIRED_CLIENTS << " clients...\n";

    while (true) {
        int sock = accept(server_fd, nullptr, nullptr);
        if (sock < 0) { std::cerr << "accept failed\n"; continue; }
        std::thread(handle_client, sock).detach();
    }

    close(server_fd);
}