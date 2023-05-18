#include "../src/Crypto.cpp" 
#include "../src/Utils.cpp" 
#include <iostream>
#include <vector>

using namespace std;

int main() {
    // Create vectors to hold the private and public keys
    vector<unsigned char> privateKey;
    vector<unsigned char> publicKey;

    // Generate the RSA key pair and store the keys in the vectors
    Crypto::generate_key_pair(privateKey, publicKey);

    cout << "Private Key:";
    cout << bytesToHex(privateKey) << endl;

    cout << "Public Key:";
    cout << bytesToHex(publicKey) << endl;

    string msg = "My message";
    vector<unsigned char> signature;
    cout << "Checkpoint" << endl;
    int ret = Crypto::generate_signature(privateKey, msg, signature);
    if(ret == -1){
        cerr << "Signature generation failed" << endl;
        exit(1);
    }
    cout << "Signature:";
    cout << bytesToHex(signature) << endl;

    bool is_valid_sign = Crypto::verify_signature(msg, signature, publicKey);
    cout << is_valid_sign << endl;
    return 0;
}