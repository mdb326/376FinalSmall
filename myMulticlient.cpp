#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <chrono>

#include "bfv.hpp"

using namespace std;

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

bool send_blob(int sock, const string& data) {
    uint32_t len = htonl(data.size());
    return send_all(sock, &len, 4) && send_all(sock, data.data(), data.size());
}

string recv_blob(int sock) {
    uint32_t len = 0;
    if (!recv_all(sock, &len, 4)) return "";

    len = ntohl(len);

    string buf(len, '\0');

    if (!recv_all(sock, &buf[0], len)) return "";

    return buf;
}

int connect_to_server(const string& ip, int port) {
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


string serialize_poly(const Poly& p) {
    stringstream ss;
    for (auto v : p) ss << v << " ";
    return ss.str();
}

Poly deserialize_poly(const string& s) {
    stringstream ss(s);
    Poly p(N);
    for (int i = 0; i < N; i++) ss >> p[i];
    return p;
}

string serialize_ct(const Ciphertext& ct) {
    return serialize_poly(ct.c0) + "|" + serialize_poly(ct.c1);
}

Ciphertext deserialize_ct(const string& s) {
    size_t sep = s.find('|');
    return {
        deserialize_poly(s.substr(0, sep)),
        deserialize_poly(s.substr(sep + 1))
    };
}

string serialize_pk(const PublicKey& pk) {
    return serialize_poly(pk.b) + "|" + serialize_poly(pk.a);
}

PublicKey deserialize_pk(const string& s) {
    size_t sep = s.find('|');
    return {
        deserialize_poly(s.substr(0, sep)),
        deserialize_poly(s.substr(sep + 1))
    };
}


int main() {
    string server_ip = "127.0.0.1";
    int port = 4040;

    int sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_PUBKEY");
    string pk_bytes = recv_blob(sock);
    close(sock);

    if (pk_bytes.empty()) {
        cerr << "Failed to get public key\n";
        return 1;
    }

    PublicKey pk = deserialize_pk(pk_bytes);

    sock = connect_to_server(server_ip, port);
    send_blob(sock, "GET_SECRETKEY");
    string sk_bytes = recv_blob(sock);
    close(sock);

    SecretKey sk;
    sk.s = deserialize_poly(sk_bytes);

    int message = 30;

    auto start = chrono::high_resolution_clock::now();

    auto enc_start = chrono::high_resolution_clock::now();
    Ciphertext ct = encrypt(pk, message);
    auto enc_end = chrono::high_resolution_clock::now();

    string ct_bytes = serialize_ct(ct);

    sock = connect_to_server(server_ip, port);
    send_blob(sock, "SUBMIT");
    send_blob(sock, ct_bytes);

    string res_bytes = recv_blob(sock);
    close(sock);

    if (res_bytes.empty()) {
        cerr << "Empty result\n";
        return 1;
    }

    Ciphertext resultCt = deserialize_ct(res_bytes);

    int result = decrypt(resultCt, sk);

    auto end = chrono::high_resolution_clock::now();

    double total_ms = chrono::duration<double, milli>(end - start).count();
    double enc_ms   = chrono::duration<double, milli>(enc_end - enc_start).count();

    cout << "encrypt_ms=" << enc_ms
         << ",total_ms=" << total_ms
         << ",result=" << result << endl;

    return 0;
}