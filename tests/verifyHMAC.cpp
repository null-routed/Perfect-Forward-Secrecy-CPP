#include "../src/Crypto.cpp" 
#include "../include/SecureBankApplication/Crypto.h"
#include <openssl/hmac.h>
#include <vector>
#include <iostream>

using namespace std;

int main() {
    std::vector<unsigned char> key1 = "good-key";
    std::vector<unsigned char> key2 = "bad-key";
    string message = "test";
    std::vector<unsigned char> hmac;

    Crypto::generateHMAC(key1, message, hmac);

    bool good_HMAC = Crypto::verifyHMAC(key1, message, hmac);
    bool bad_HMAC = Crypto::verifyHMAC(key2, message, hmac);

    if (good_HMAC && !bad_HMAC) {
        std::cout << "Works fine";
    } else {
        std::cout << "Something is wrong";
    }

    return 0;
}