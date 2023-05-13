#include <iostream>
#include "../include/SecureBankApplication/Crypto.h"
#include "../src/Crypto.cpp"
#include <string> 
#include <vector>
using namespace std;

int main() {

    string msg = "My very secret message!";
    vector<unsigned char> enc_msg;
    vector<unsigned char> key = "0123456789abcdef";
    int ret = Crypto::encryptMessage(key, msg, enc_msg);
    if(ret == -1){
        cerr << "Encryption failed" << endl;
        exit(1);
    }

    // verifying the message has indeed been overwritten
    cout << msg << endl;

    // verifying that the enc messaged actually decrypts to the original message
    string msg1 = Crypto::decryptMessage(key, enc_msg, msg1);

    cout << msg1 << endl;
    return 0;
}