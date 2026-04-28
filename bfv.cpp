#include <iostream>
#include <vector>
#include <random>
#include <cmath>

using namespace std;

const int N = 16;
const int64_t q = 1 << 15; // 32768
const int64_t t = 4; //modulus
const int64_t DELTA = q / t;

random_device rd;
mt19937 gen(rd());


vector<int64_t> sample_ternary() {
    uniform_int_distribution<int> dist(-1, 1);
    vector<int64_t> res(N);
    for (int i = 0; i < N; i++) res[i] = dist(gen);
    return res;
}

vector<int64_t> sample_uniform() {
    uniform_int_distribution<int64_t> dist(0, q - 1);
    vector<int64_t> res(N);
    for (int i = 0; i < N; i++) res[i] = dist(gen);
    return res;
}

vector<int64_t> sample_noise() {
    uniform_int_distribution<int> dist(-2, 2);
    vector<int64_t> res(N);
    for (int i = 0; i < N; i++) res[i] = dist(gen);
    return res;
}

vector<int64_t> poly_add(const vector<int64_t> &a, const vector<int64_t> &b) {
    vector<int64_t> res(N);
    for (int i = 0; i < N; i++) {
        res[i] = (a[i] + b[i]) % q;
        if (res[i] < 0) res[i] += q;
    }
    return res;
}

vector<int64_t> poly_scalar(const vector<int64_t> &a, int64_t scalar) {
    vector<int64_t> res(N);
    for (int i = 0; i < N; i++) {
        res[i] = (a[i] * scalar) % q;
        if (res[i] < 0) res[i] += q;
    }
    return res;
}

vector<int64_t> poly_mul(const vector<int64_t> &a, const vector<int64_t> &b) {
    vector<int64_t> res(N, 0);

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            int idx = (i + j) % N;
            int sign = ((i + j) < N) ? 1 : -1;

            res[idx] += sign * a[i] * b[j];
        }
    }

    for (int i = 0; i < N; i++) {
        res[i] %= q;
        if (res[i] < 0) res[i] += q;
    }

    return res;
}


struct PublicKey {
    vector<int64_t> b;
    vector<int64_t> a;
};

struct SecretKey {
    vector<int64_t> s;
};

pair<PublicKey, SecretKey> keygen() {
    vector<int64_t> s = sample_ternary();
    vector<int64_t> a = sample_uniform();
    vector<int64_t> e = sample_noise();

    vector<int64_t> a_s = poly_mul(a, s);

    vector<int64_t> b(N);
    for (int i = 0; i < N; i++) {
        b[i] = (-a_s[i] + e[i]) % q;
        if (b[i] < 0) b[i] += q;
    }

    return {{b, a}, {s}};
}


struct Ciphertext {
    vector<int64_t> c0;
    vector<int64_t> c1;
};

Ciphertext encrypt(const PublicKey &pk, int m) {
    vector<int64_t> u = sample_ternary();
    vector<int64_t> e1 = sample_noise();
    vector<int64_t> e2 = sample_noise();

    //encode message
    vector<int64_t> m_poly(N, 0);
    m_poly[0] = (m % t + t) % t;

    vector<int64_t> scaled_m = poly_scalar(m_poly, DELTA);

    vector<int64_t> bu = poly_mul(pk.b, u);
    vector<int64_t> au = poly_mul(pk.a, u);

    vector<int64_t> c0 = poly_add(poly_add(bu, e1), scaled_m);
    vector<int64_t> c1 = poly_add(au, e2);

    return {c0, c1};
}

int decrypt(const Ciphertext &ct, const SecretKey &sk) {
    vector<int64_t> c1s = poly_mul(ct.c1, sk.s);
    vector<int64_t> x = poly_add(ct.c0, c1s);

    // Recover message from constant term
    double val = (double)x[0] / (double)DELTA;
    int m = (int)round(val) % t;

    if (m < 0) m += t;
    return m;
}

// Debug printing
void print_poly(const vector<int64_t> &p, const string &name) {
    cout << name << ": [ ";
    for (auto v : p) cout << v << " ";
    cout << "]\n";
}


int main() {
    auto [pk, sk] = keygen();

    int message = 3;

    cout << "Original message: " << message << endl;

    Ciphertext ct = encrypt(pk, message);

    int decrypted = decrypt(ct, sk);

    cout << "Decrypted message: " << decrypted << endl;

    return 0;
}