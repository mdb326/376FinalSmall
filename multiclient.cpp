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
#include "scheme/bfvrns/bfvrns-ser.h"
#include "key/key-ser.h"

CEREAL_REGISTER_DYNAMIC_INIT(bfvrns_ser)
CEREAL_REGISTER_DYNAMIC_INIT(key_ser)

using namespace lbcrypto;

// ---------------- ARG PARSER ----------------
std::map<std::string, std::string> parse_args(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc - 1; i += 2)
        args[argv[i]] = argv[i + 1];
    return args;
}

// ---------------- SOCKET HELPERS ----------------
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
        perror("connect");
        return -1;
    }
    return sock;
}

// ---------------- MAIN ----------------
int main(int argc, char* argv[]) {
    auto args = parse_args(argc, argv);

    int         vec_size   = args.count("--vec_size")   ? std::stoi(args["--vec_size"])   : 8;
    std::string value_type = args.count("--value_type") ? args["--value_type"]            : "CONST";
    int64_t     const_val  = args.count("--value")      ? std::stoll(args["--value"])     : 1;
    int         seed       = args.count("--seed")       ? std::stoi(args["--seed"])       : 42;
    std::string server_ip  = args.count("--server_ip")  ? args["--server_ip"]             : "127.0.0.1";
    int         port       = args.count("--port")       ? std::stoi(args["--port"])       : 4040;
    int         repeat     = args.count("--repeat")     ? std::stoi(args["--repeat"])     : 1;

    std::mt19937 gen(seed);
    std::uniform_int_distribution<int64_t> dist(0, 10);

    // -------- GET CONTEXT --------
    int sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_CONTEXT");
    std::string cc_bytes = recv_blob(sock);
    close(sock);

    if (cc_bytes.empty()) {
        std::cerr << "Failed to get context\n";
        return 1;
    }

    CryptoContext<DCRTPoly> cc;
    { std::stringstream ss(cc_bytes); Serial::Deserialize(cc, ss, SerType::BINARY); }

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // -------- GET PUBKEY --------
    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_PUBKEY");
    std::string pk_bytes = recv_blob(sock);
    close(sock);

    PublicKey<DCRTPoly> pubKey;
    { std::stringstream ss(pk_bytes); Serial::Deserialize(pubKey, ss, SerType::BINARY); }

    // -------- GET EVAL KEY --------
    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_EVALKEY");
    std::string ek_bytes = recv_blob(sock);
    close(sock);

    { std::stringstream ss(ek_bytes); cc->DeserializeEvalMultKey(ss, SerType::BINARY); }

    // -------- GET SECRET KEY (DEV ONLY) --------
    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_SECRETKEY");
    std::string sk_bytes = recv_blob(sock);
    close(sock);

    PrivateKey<DCRTPoly> secretKey;
    { std::stringstream ss(sk_bytes); Serial::Deserialize(secretKey, ss, SerType::BINARY); }

    // -------- BENCH LOOP --------
    double total_time = 0;

    for (int r = 0; r < repeat; r++) {

        // -------- Generate integer data --------
        std::vector<int64_t> data(vec_size);
        for (int i = 0; i < vec_size; i++) {
            data[i] = (value_type == "RANDOM") ? dist(gen) : const_val;
        }

        auto start = std::chrono::high_resolution_clock::now();

        // -------- Encrypt --------
        auto enc_start = std::chrono::high_resolution_clock::now();
        Plaintext pt = cc->MakePackedPlaintext(data);
        auto ct      = cc->Encrypt(pubKey, pt);
        auto enc_end = std::chrono::high_resolution_clock::now();

        // -------- Serialize --------
        std::string ct_bytes;
        { std::stringstream ss; Serial::Serialize(ct, ss, SerType::BINARY); ct_bytes = ss.str(); }

        size_t ciphertext_size = ct_bytes.size();

        // -------- Submit --------
        sock = connect_to_server(server_ip, port);
        send_blob(sock, "SUBMIT");
        send_blob(sock, ct_bytes);

        std::string res_bytes = recv_blob(sock);
        close(sock);

        if (res_bytes.empty()) {
            std::cerr << "Empty result\n";
            continue;
        }

        // -------- Deserialize result --------
        Ciphertext<DCRTPoly> resultCt;
        { std::stringstream ss(res_bytes); Serial::Deserialize(resultCt, ss, SerType::BINARY); }

        // -------- Decrypt --------
        Plaintext resultPt;
        cc->Decrypt(secretKey, resultCt, &resultPt);
        resultPt->SetLength(vec_size);

        auto vals = resultPt->GetPackedValue();

        auto end = std::chrono::high_resolution_clock::now();

        double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double enc_ms   = std::chrono::duration<double, std::milli>(enc_end - enc_start).count();
        total_time += total_ms;

        // -------- CSV OUTPUT --------
        std::cout << "vector_size=" << vec_size
                  << ",encrypt_ms=" << enc_ms
                  << ",total_ms=" << total_ms
                  << ",ciphertext_bytes=" << ciphertext_size
                  << ",result=[";

        // for (size_t i = 0; i < vals.size(); i++) {
        //     std::cout << vals[i];
        //     if (i + 1 < vals.size()) std::cout << ",";
        // }
        std::cout << "]\n";
    }

    std::cout << "avg_total_ms=" << (total_time / repeat) << "\n";
    return 0;
}