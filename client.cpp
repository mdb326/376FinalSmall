#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include "openfhe.h"
#include "utils/serial.h"
#include <cryptocontext-ser.h>
#include "scheme/bfvrns/bfvrns-ser.h"
#include "key/key-ser.h"
#include <chrono>

CEREAL_REGISTER_DYNAMIC_INIT(bfvrns_ser)
CEREAL_REGISTER_DYNAMIC_INIT(key_ser)

using namespace lbcrypto;


bool recv_all(int sock, void* buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t r = recv(sock, (char*)buf + received, len - received, 0);
        if (r <= 0) return false;
        received += r;
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
    return send_all(sock, &len, sizeof(len)) &&
           send_all(sock, data.data(), data.size());
}

std::string recv_blob(int sock) {
    uint32_t len;
    if (!recv_all(sock, &len, sizeof(len))) return "";

    len = ntohl(len);
    std::string buffer(len, '\0');

    if (!recv_all(sock, buffer.data(), len)) return "";

    return buffer;
}


int main() {
    std::vector<double> data = {1.1, 2.2, 3.3, 4.4};
    for(double i = 5; i < 8; i++){
        data.push_back(i);
    }

        std::string server_ip = "127.0.0.1";
    int port = 4040;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &serverAddr.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect");
        return 1;
    }

    std::cout << "Connected to server\n";

    auto start = std::chrono::steady_clock::now();

    // CCParams<CryptoContextBFVRNS> parameters; //int
    CCParams<CryptoContextCKKSRNS> parameters; //double
    // parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

    //double only values
    parameters.SetScalingModSize(50);   // precision control
    parameters.SetBatchSize(8);         // number of slots

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();


    // encode
    //  Plaintext pt = cryptoContext->MakePackedPlaintext(data);
    Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(data);

    // encrypt
    auto ct = cryptoContext->Encrypt(keyPair.publicKey, pt);

    std::stringstream ct_stream;
    Serial::Serialize(ct, ct_stream, SerType::BINARY);
    std::string ct_bytes = ct_stream.str();


    //eval keys
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::stringstream ek_stream;
    cryptoContext->SerializeEvalMultKey(ek_stream, SerType::BINARY);
    std::string ek_bytes = ek_stream.str();


    if (!send_blob(sock, ek_bytes)) {
        std::cerr << "Failed to send eval keys\n";
        return 1;
    }

    uint32_t vec_size = htonl(data.size());
    if (!send_all(sock, &vec_size, sizeof(vec_size))) {
        std::cerr << "Failed to send vector length\n";
        return 1;
    }
    

    if (!send_blob(sock, ct_bytes)) {
        std::cerr << "Failed to send ciphertext\n";
        return 1;
    }

    std::cout << "Sent encrypted data\n";

    std::string res_bytes = recv_blob(sock);

    if (res_bytes.empty()) {
        std::cerr << "Failed to receive result\n";
        return 1;
    }

    Ciphertext<DCRTPoly> resultCt;
    std::stringstream res_stream(res_bytes);
    Serial::Deserialize(resultCt, res_stream, SerType::BINARY);

    // decrypt
    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, resultCt, &result);
    result->SetLength(data.size());

    // auto vals = result->GetPackedValue();
    auto vals = result->GetCKKSPackedValue();

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    std::cout << "Elapsed time: " << elapsed.count() << "s\n";

std::cout << "Full result: [";
for (size_t i = 0; i < vals.size(); i++) {
    std::cout << vals[i];
    if (i + 1 < vals.size()) std::cout << ", ";
}
std::cout << "]\n";

    close(sock);
    return 0;
}
