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
    vector<unsigned char> salt; // empty salt
    bool ret = Crypto::hash_with_salt(password, hash, salt);
    if(!ret){
        cout << "Hashing failed" << endl;
        exit(1);
    }
    cout << "Your hash: ";
    cout << bytesToHex(hash) << endl;
    return 0;
}