#include "../src/Crypto.cpp" 
#include "../include/SecureBankApplication/Crypto.h"
#include "../src/Utils.cpp" 
#include "../include/SecureBankApplication/Utils.h"
#include <iostream>
#include <vector>

using namespace std;

int main() {
    string password = "MyPa$$word!";
    vector<unsigned char> hash; 

    bool ret = Crypto::hashWithSalt(password, hash);
    if(!ret){
        cout << "Hashing failed" << endl;
        exit(1);
    }
    cout << "Your hash: ";
    cout << bytesToHex(hash) << endl;
    return 0;
}