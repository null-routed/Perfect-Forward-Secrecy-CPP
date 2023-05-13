#include "../src/Crypto.cpp" 
#include "../include/SecureBankApplication/Crypto.h"
#include <openssl/hmac.h>
#include <vector>
#include <iostream>

using namespace std;

void print(std::vector <unsigned char> const &a) {
   std::cout << "Generated HMAC : ";

   for(int i=0; i < a.size(); i++)
   std::cout << a.at(i) << ' ';
}

int main() {
    std::vector<unsigned char> key = { 'f', 'o', 'o' };
    std::vector<unsigned char> message = { 'd', 'u', 'p', 'a' };
    std::vector<unsigned char> hmac;

    Crypto::generateHMAC(key, message, hmac);
    print(hmac);

    return 0;
}