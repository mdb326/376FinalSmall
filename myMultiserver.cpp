#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>

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


int main() {
    int port = 4040;

    auto [pk, sk] = keygen();

    cout << "Server started on port " << port << endl;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    vector<Ciphertext> pending_cts;
    vector<int> pending_clients;

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);

        string command = recv_blob(client);

        if (command == "GET_PUBKEY") {
            send_blob(client, serialize_pk(pk));
            close(client);
        }

        else if (command == "GET_SECRETKEY") {
            send_blob(client, serialize_poly(sk.s));
            close(client);
        }

        else if (command == "SUBMIT") {
            string ct_bytes = recv_blob(client);

            if (ct_bytes.empty()) {
                close(client);
                continue;
            }

            Ciphertext ct = deserialize_ct(ct_bytes);

            pending_cts.push_back(ct);
            pending_clients.push_back(client);

            cout << "Received ciphertext (" << pending_cts.size() << "/3)\n";

            if (pending_cts.size() == 3) {
                cout << "Computing sum of 3 ciphertexts...\n";

                Ciphertext result = pending_cts[0];

                for (int i = 1; i < 3; i++) {
                    result = add(result, pending_cts[i]);
                }

                string out = serialize_ct(result);

                for (int sock : pending_clients) {
                    send_blob(sock, out);
                    close(sock);
                }

                pending_cts.clear();
                pending_clients.clear();
            }

        }

        else {
            close(client);
        }
    }

    return 0;
}