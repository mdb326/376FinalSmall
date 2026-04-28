#include <iostream>
#include <vector>
#include <random>
#include <cmath>

using namespace std;

using Poly = vector<int64_t>;

// Parameters
const int N = 16;
const int64_t q = 1 << 15; // 32768
const int64_t t = 4;
const int64_t DELTA = q / t;

// RNG
random_device rd;
mt19937 gen(rd());

// ------------------------
// Sampling
// ------------------------

Poly sample_ternary() {
    uniform_int_distribution<int> dist(-1, 1);
    Poly res(N);
    for (int i = 0; i < N; i++) res[i] = dist(gen);
    return res;
}

Poly sample_uniform() {
    uniform_int_distribution<int64_t> dist(0, q - 1);
    Poly res(N);
    for (int i = 0; i < N; i++) res[i] = dist(gen);
    return res;
}

Poly sample_noise() {
    uniform_int_distribution<int> dist(-2, 2);
    Poly res(N);
    for (int i = 0; i < N; i++) res[i] = dist(gen);
    return res;
}

// ------------------------
// Poly arithmetic
// ------------------------

Poly poly_add(const Poly &a, const Poly &b) {
    Poly res(N);
    for (int i = 0; i < N; i++) {
        res[i] = (a[i] + b[i]) % q;
        if (res[i] < 0) res[i] += q;
    }
    return res;
}

Poly poly_scalar(const Poly &a, int64_t scalar) {
    Poly res(N);
    for (int i = 0; i < N; i++) {
        res[i] = (a[i] * scalar) % q;
        if (res[i] < 0) res[i] += q;
    }
    return res;
}

Poly poly_mul(const Poly &a, const Poly &b) {
    Poly res(N, 0);

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

// ------------------------
// Keys
// ------------------------

struct PublicKey {
    Poly b;
    Poly a;
};

struct SecretKey {
    Poly s;
};

pair<PublicKey, SecretKey> keygen() {
    Poly s = sample_ternary();
    Poly a = sample_uniform();
    Poly e = sample_noise();

    Poly a_s = poly_mul(a, s);

    Poly b(N);
    for (int i = 0; i < N; i++) {
        b[i] = (-a_s[i] + e[i]) % q;
        if (b[i] < 0) b[i] += q;
    }

    return {{b, a}, {s}};
}

// ------------------------
// Encryption
// ------------------------

struct Ciphertext {
    Poly c0;
    Poly c1;
};

Ciphertext encrypt(const PublicKey &pk, int m) {
    Poly u = sample_ternary();
    Poly e1 = sample_noise();
    Poly e2 = sample_noise();

    // Encode message
    Poly m_poly(N, 0);
    m_poly[0] = (m % t + t) % t;

    Poly scaled_m = poly_scalar(m_poly, DELTA);

    Poly bu = poly_mul(pk.b, u);
    Poly au = poly_mul(pk.a, u);

    Poly c0 = poly_add(poly_add(bu, e1), scaled_m);
    Poly c1 = poly_add(au, e2);

    return {c0, c1};
}

// ------------------------
// Decryption
// ------------------------

int decrypt(const Ciphertext &ct, const SecretKey &sk) {
    Poly c1s = poly_mul(ct.c1, sk.s);
    Poly x = poly_add(ct.c0, c1s);

    // Recover message from constant term
    double val = (double)x[0] / (double)DELTA;
    int m = (int)round(val) % t;

    if (m < 0) m += t;
    return m;
}

// ------------------------
// Debug
// ------------------------

void print_poly(const Poly &p, const string &name) {
    cout << name << ": [ ";
    for (auto v : p) cout << v << " ";
    cout << "]\n";
}

// ------------------------
// Main test
// ------------------------

int main() {
    auto [pk, sk] = keygen();

    int message = 3;

    cout << "Original message: " << message << endl;

    Ciphertext ct = encrypt(pk, message);

    int decrypted = decrypt(ct, sk);

    cout << "Decrypted message: " << decrypted << endl;

    return 0;
}