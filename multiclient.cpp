#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <chrono>

#include "openfhe.h"
#include "utils/serial.h"
#include <cryptocontext-ser.h>
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"

CEREAL_REGISTER_DYNAMIC_INIT(ckksrns_ser)
CEREAL_REGISTER_DYNAMIC_INIT(key_ser)

using namespace lbcrypto;

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

    // ── step 1: fetch the server's crypto context ─────────────────────────────
    int sock = connect_to_server();
    if (sock < 0) return 1;
    send_blob(sock, "GET_CONTEXT");
    std::string cc_bytes = recv_blob(sock);
    close(sock);
    if (cc_bytes.empty()) { std::cerr << "Failed to get crypto context\n"; return 1; }

    CryptoContext<DCRTPoly> cc;
    { std::stringstream ss(cc_bytes); Serial::Deserialize(cc, ss, SerType::BINARY); }
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    std::cout << "Crypto context received\n";

    // ── step 2: fetch public key ──────────────────────────────────────────────
    sock = connect_to_server();
    if (sock < 0) return 1;
    send_blob(sock, "GET_PUBKEY");
    std::string pk_bytes = recv_blob(sock);
    close(sock);
    if (pk_bytes.empty()) { std::cerr << "Failed to get public key\n"; return 1; }

    PublicKey<DCRTPoly> pubKey;
    { std::stringstream ss(pk_bytes); Serial::Deserialize(pubKey, ss, SerType::BINARY); }
    std::cout << "Public key received\n";

    // ── step 3: fetch eval key ────────────────────────────────────────────────
    sock = connect_to_server();
    if (sock < 0) return 1;
    send_blob(sock, "GET_EVALKEY");
    std::string ek_bytes = recv_blob(sock);
    close(sock);
    if (ek_bytes.empty()) { std::cerr << "Failed to get eval key\n"; return 1; }

    { std::stringstream ss(ek_bytes); cc->DeserializeEvalMultKey(ss, SerType::BINARY); }
    std::cout << "Eval key received\n";

    // ── step 4: encrypt and submit ────────────────────────────────────────────
    Plaintext pt = cc->MakeCKKSPackedPlaintext(data);
    auto ct      = cc->Encrypt(pubKey, pt);

    std::string ct_bytes;
    { std::stringstream ss; Serial::Serialize(ct, ss, SerType::BINARY); ct_bytes = ss.str(); }

    sock = connect_to_server();
    if (sock < 0) return 1;
    send_blob(sock, "SUBMIT");
    if (!send_blob(sock, ct_bytes)) { std::cerr << "Failed to send ciphertext\n"; return 1; }
    std::cout << "Submitted — waiting for all clients...\n";

    // ── step 5: block until server sends the sum ──────────────────────────────
    std::string res_bytes = recv_blob(sock);
    close(sock);
    if (res_bytes.empty()) { std::cerr << "Failed to receive result\n"; return 1; }

    Ciphertext<DCRTPoly> resultCt;
    { std::stringstream ss(res_bytes); Serial::Deserialize(resultCt, ss, SerType::BINARY); }
    std::cout << "Result received\n";

    // ── step 6: request secret key and decrypt (dev only) ─────────────────────
    sock = connect_to_server();
    if (sock < 0) return 1;
    send_blob(sock, "GET_SECRETKEY");
    std::string sk_bytes = recv_blob(sock);
    close(sock);

    PrivateKey<DCRTPoly> secretKey;
    { std::stringstream ss(sk_bytes); Serial::Deserialize(secretKey, ss, SerType::BINARY); }

    Plaintext result;
    cc->Decrypt(secretKey, resultCt, &result);
    result->SetLength(data.size());

    auto vals = result->GetCKKSPackedValue();
    std::cout << "Decrypted sum: [";
    for (size_t i = 0; i < vals.size(); i++) {
        std::cout << vals[i].real();
        if (i + 1 < vals.size()) std::cout << ", ";
    }
    std::cout << "]\n";

    auto end = std::chrono::steady_clock::now();
    std::cout << "Elapsed: "
              << std::chrono::duration<double>(end - start).count() << "s\n";

    return 0;
}