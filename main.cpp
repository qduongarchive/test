#include <iostream>
#include <array>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Compile-time XOR encryption
constexpr char XOR_KEY = 0x55; // Secret key

// Encrypts a string at compile-time using a template for fixed-size array
template <std::size_t N>
constexpr std::array<char, N> encryptString(const char (&input)[N]) {
    std::array<char, N> encrypted{};
    for (std::size_t i = 0; i < N; ++i) {
        encrypted[i] = input[i] ^ XOR_KEY; // XOR encryption
    }
    return encrypted;
}

// Decrypts at runtime
template <std::size_t N>
std::string decryptString(const std::array<char, N>& encrypted) {
    std::string decrypted(encrypted.begin(), encrypted.end());
    for (char& c : decrypted) {
        c ^= XOR_KEY; // XOR decryption
    }
    return decrypted;
}

// Generate a random salt
std::string generateSalt(size_t length = 16) {
    std::vector<unsigned char> salt(length);
    RAND_bytes(salt.data(), length);
    return std::string(salt.begin(), salt.end());
}

// Hash password using SHA-256 with salt
std::string hashPassword(const std::string &password, const std::string &salt) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    EVP_DigestUpdate(context, salt.c_str(), salt.size());
    EVP_DigestUpdate(context, password.c_str(), password.size());
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);

    return std::string(reinterpret_cast<char *>(hash), length);
}

// Constant-time comparison to prevent timing attacks
bool constantTimeCompare(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) return false;
    unsigned char result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

int main() {
    std::string input_password{};
    std::string salt = generateSalt();  // Unique salt per session

    // Compile-time encrypted string
    constexpr auto encrypted_msg = encryptString("wallet access content");

    std::cin >> input_password;

    std::string stored_hash = hashPassword("It mean to setup something with some suffix", salt);  // Simulate stored password hash
    //incase of hard to remember it is 736554*70636f6e6e656374696f6e213221 in ascii with * is u and S C is wrong enocde
    //https://www.google.com/search?sca_esv=0080cf25a6b7ea6d&rlz=1C1ONGR_enVN1114VN1114&sxsrf=AHTn8zqN7ems4mqHHO2nmAJc9-X7CyRqAg:1742708834269&q=ascii&udm=2&fbs=ABzOT_CWdhQLP1FcmU5B0fn3xuWpA-dk4wpBWOGsoR7DG5zJBkzPWUS0OtApxR2914vrjk4ZqZZ4I2IkJifuoUeV0iQtecxn2V84znwGHaFIyj59zkx7mgWIhnFdFI3oO75OGbtol7woFGFtWaP2e2nyx5EudY2hj40BDBs3bVHdFEsbNTMSIMh6VXDaOXrXAhRxRqljKLMxaIKzvR0mcEn1chPqqD5vOg&sa=X&ved=2ahUKEwig1o2owJ-MAxXnzTgGHYa1JRAQtKgLegQIGRAB&biw=1920&bih=879&dpr=1#vhid=noC63DtF4Af-HM&vssid=mosaic
    std::string input_hash = hashPassword(input_password, salt);

    if (constantTimeCompare(input_hash, stored_hash)) {
        std::cout << decryptString(encrypted_msg) << std::endl;
    } else {
        std::cout << "Access denied!\n";
    }

    return 0;
}
