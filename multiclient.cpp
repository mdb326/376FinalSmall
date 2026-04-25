#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <chrono>
#include <random>
#include <map>

#include "openfhe.h"
#include "utils/serial.h"
#include <cryptocontext-ser.h>
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"

CEREAL_REGISTER_DYNAMIC_INIT(ckksrns_ser)
CEREAL_REGISTER_DYNAMIC_INIT(key_ser)

using namespace lbcrypto;

std::map<std::string, std::string> parse_args(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc - 1; i += 2)
        args[argv[i]] = argv[i + 1];
    return args;
}

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

    // ── fetch context, keys once — reuse across repeats ──────────────────────
    int sock;

    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_CONTEXT");
    std::string cc_bytes = recv_blob(sock);
    close(sock);
    if (cc_bytes.empty()) { std::cerr << "Failed to get context\n"; return 1; }

    CryptoContext<DCRTPoly> cc;
    { std::stringstream ss(cc_bytes); Serial::Deserialize(cc, ss, SerType::BINARY); }
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_PUBKEY");
    std::string pk_bytes = recv_blob(sock);
    close(sock);
    if (pk_bytes.empty()) { std::cerr << "Failed to get public key\n"; return 1; }

    PublicKey<DCRTPoly> pubKey;
    { std::stringstream ss(pk_bytes); Serial::Deserialize(pubKey, ss, SerType::BINARY); }

    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_EVALKEY");
    std::string ek_bytes = recv_blob(sock);
    close(sock);
    if (ek_bytes.empty()) { std::cerr << "Failed to get eval key\n"; return 1; }
    { std::stringstream ss(ek_bytes); cc->DeserializeEvalMultKey(ss, SerType::BINARY); }

    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_SECRETKEY");
    std::string sk_bytes = recv_blob(sock);
    close(sock);
    if (sk_bytes.empty()) { std::cerr << "Failed to get secret key\n"; return 1; }

    PrivateKey<DCRTPoly> secretKey;
    { std::stringstream ss(sk_bytes); Serial::Deserialize(secretKey, ss, SerType::BINARY); }

    // ── repeat loop ───────────────────────────────────────────────────────────
    double total_time = 0;

    for (int r = 0; r < repeat; r++) {

        // ── generate data ─────────────────────────────────────────────────────
        std::vector<double> data(vec_size);
        for (int i = 0; i < vec_size; i++)
            data[i] = (value_type == "RANDOM") ? dist(gen) : const_val;

        auto start = std::chrono::high_resolution_clock::now();

        // ── encrypt ───────────────────────────────────────────────────────────
        auto enc_start = std::chrono::high_resolution_clock::now();
        Plaintext pt = cc->MakeCKKSPackedPlaintext(data);
        auto ct      = cc->Encrypt(pubKey, pt);
        auto enc_end = std::chrono::high_resolution_clock::now();

        std::string ct_bytes;
        { std::stringstream ss; Serial::Serialize(ct, ss, SerType::BINARY); ct_bytes = ss.str(); }

        size_t ciphertext_size = ct_bytes.size();

        // ── submit and wait for result ────────────────────────────────────────
        sock = connect_to_server(server_ip, port);
        send_blob(sock, "SUBMIT");
        send_blob(sock, ct_bytes);

        std::string res_bytes = recv_blob(sock);
        close(sock);

        if (res_bytes.empty()) { std::cerr << "Empty result on repeat " << r << "\n"; continue; }

        // ── deserialize and decrypt result ────────────────────────────────────
        Ciphertext<DCRTPoly> resultCt;
        { std::stringstream ss(res_bytes); Serial::Deserialize(resultCt, ss, SerType::BINARY); }

        Plaintext resultPt;
        cc->Decrypt(secretKey, resultCt, &resultPt);
        resultPt->SetLength(vec_size);
        auto vals = resultPt->GetCKKSPackedValue();

        auto end = std::chrono::high_resolution_clock::now();

        double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double enc_ms   = std::chrono::duration<double, std::milli>(enc_end - enc_start).count();
        total_time += total_ms;

        // ── CSV log ───────────────────────────────────────────────────────────
        std::cout << "vector_size=" << vec_size
                  << ",mode=" << mode
                  << ",encrypt_ms=" << enc_ms
                  << ",total_ms=" << total_ms
                  << ",ciphertext_bytes=" << ciphertext_size;
        for (size_t i = 0; i < vals.size(); i++)
            std::cout << vals[i].real() << (i + 1 < vals.size() ? "," : "");
        std::cout << "]\n";
    }

    std::cout << "avg_total_ms=" << (total_time / repeat) << "\n";
    return 0;
}