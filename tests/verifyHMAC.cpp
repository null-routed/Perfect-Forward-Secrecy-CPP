#include "../src/Crypto.cpp" 
#include "../include/SecureBankApplication/Crypto.h"
#include <openssl/hmac.h>
#include <vector>
#include <iostream>

using namespace std;

void print(std::vector <unsigned char> const &a) {
   std::cout << "The vector elements are : ";

   for(int i=0; i < a.size(); i++)
   std::cout << a.at(i) << ' ';
}

int main() {
    std::vector<unsigned char> key1 = { '2', '1', '3', '7' };
    std::vector<unsigned char> key2 = { '7', '3', '1', '2' };
    std::vector<unsigned char> message = { 'd', 'u', 'p', 'a' };
    std::vector<unsigned char> hmac;

    Crypto::generateHMAC(key1, message, hmac);

    bool good_HMAC = verifyHMAC(key1, message, hmac);
    bool bad_HMAC = verifyHMAC(key2, message, hmac);

    if (good_HMAC && !bad_HMAC) {
        std::cout << "Works fine";
    } else {
        std::cout << "Something is wrong";
    }

    return 0;
}