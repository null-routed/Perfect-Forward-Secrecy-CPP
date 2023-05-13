#include <iostream>
#include "../include/SecureBankApplication/Crypto.h"
#include "../src/Crypto.cpp"
using namespace std;

int main() {

    for(int i = 0; i < 20; i++){
        cout << Crypto::generateNonce(10) << endl;
    }
}