#include "../src/Crypto.cpp" 
#include "../include/SecureBankApplication/Crypto.h"
#include "../src/Utils.cpp" 
#include "../include/SecureBankApplication/Utils.h"
#include <iostream>
#include <vector>

using namespace std;

int main() {
    // Create vectors to hold the private and public keys
    vector<unsigned char> privateKey;
    vector<unsigned char> publicKey;

    // Generate the RSA key pair and store the keys in the vectors
    Crypto::generateKeyPair(privateKey, publicKey);

    cout << "Private Key:";
    cout << bytesToHex(privateKey) << endl;

    cout << "Public Key:";
    cout << bytesToHex(publicKey) << endl;

    string msg = "My message";
    vector<unsigned char> signature;
    int ret = generateSignature(privateKey, msg, signature);
    if(ret == -1){
        cerr << "Signature generation failed" << endl;
        exit(1);
    }
    cout << "Signature:";
    cout << bytesToHex(signature) << endl;
    return 0;
}