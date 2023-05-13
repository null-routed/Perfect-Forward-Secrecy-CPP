#include "../src/Utils.cpp" 
#include "../include/SecureBankApplication/Transaction.h"
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int main(){

    Message msg = {"123", "456", 1, "abcde", "HELLO_SERVER", "abcd"};

    vector<unsigned char> serialized = serializeMessage(msg);
    string printableString(serialized.begin(), serialized.end());
    cout << printableString << endl;

    Message msg1 = deserializeMessage(serialized);
    vector<unsigned char> serialized1 = serializeMessage(msg1);
    string printableString1(serialized1.begin(), serialized1.end());
    cout << printableString1 << endl;
    
    return 0;
}