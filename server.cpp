#include <iostream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <cstring>
#include <atomic>
#include <algorithm>
#include <thread>
#include <mutex>
#include <map>
#include <random>
#include "openfhe.h"
#include <cryptocontext-ser.h>
#include "scheme/bfvrns/bfvrns-ser.h"
#include "key/key-ser.h"

CEREAL_REGISTER_DYNAMIC_INIT(bfvrns_ser)
CEREAL_REGISTER_DYNAMIC_INIT(key_ser)

using namespace lbcrypto;


template <typename T>
std::vector<uint8_t> serialize_raw(const T& val) {
    std::vector<uint8_t> bytes(sizeof(T));
    std::memcpy(bytes.data(), &val, sizeof(T));
    return bytes;
}

int generateRandomInteger(int min, int max) {
    thread_local static std::random_device rd;
    thread_local static std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(min, max);
    return distrib(gen);
}

std::vector<std::string> getProcesses(std::string filename){
    std::ifstream config(filename);
    std::vector<std::string> result;
    std::string line;

    while (std::getline(config, line)) {
        if (line == "Servers:" || line.empty()) continue;
        result.push_back(line);
    }

    config.close(); 
    return result;
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


int main(int argc, char* argv[]) {
    std::vector<std::string> processIPS = getProcesses("config.txt");

    int port = 4040;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0){
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&serverAddress,
         sizeof(serverAddress)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 100) < 0) {
        perror("listen");
        return 1;
    }

    std::cout << "Server listening on port " << port << std::endl;

    while (true) {
        int clientSocket = accept(server_fd, nullptr, nullptr);
        if (clientSocket < 0) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        std::cout << "Client connected: socket=" << clientSocket << std::endl;


        // CCParams<CryptoContextBFVRNS> parameters; //int
        CCParams<CryptoContextCKKSRNS> parameters; //double
        // parameters.SetPlaintextModulus(65537);
        parameters.SetMultiplicativeDepth(2);

        //double only values
        parameters.SetScalingModSize(50);   // precision control
        parameters.SetBatchSize(8);         // number of slots

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);

        // eval keys
        std::string ek_bytes = recv_blob(clientSocket);
        std::stringstream ek_stream(ek_bytes);
        cc->DeserializeEvalMultKey(ek_stream, SerType::BINARY);

        //length
        uint32_t vec_size;
        recv_all(clientSocket, &vec_size, sizeof(vec_size));
        vec_size = ntohl(vec_size);


        // ciphertext
        Ciphertext<DCRTPoly> ct;
        std::string ct_bytes = recv_blob(clientSocket);
        std::stringstream ct_stream(ct_bytes);
        Serial::Deserialize(ct, ct_stream, SerType::BINARY);

        std::vector<double> scalarVec(vec_size, 5.0);
        // Plaintext scalar = cc->MakePackedPlaintext(scalarVec);
        Plaintext scalar = cc->MakeCKKSPackedPlaintext(scalarVec);

        auto result = cc->EvalMult(ct, scalar);

        std::stringstream res_stream;
        Serial::Serialize(result, res_stream, SerType::BINARY);
        std::string res_bytes = res_stream.str();

        if (!send_blob(clientSocket, res_bytes)) {
            std::cerr << "Failed to send result\n";
        }

        close(clientSocket);
    }

    close(server_fd);
    return 0;
}
