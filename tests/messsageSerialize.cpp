#include "../src/Utils.cpp" 
#include "../include/SecureBankApplication/Transaction.h"
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int main(){

    Message msg = {"123", "456", 1, "abcde", "HELLO_SERVER", "abcd"};

    string serialized = serializeMessage(msg);
    cout << serialized << endl;

    Message msg1 = deserializeMessage(serialized);
    string serialized1 = serializeMessage(msg1);
    string printableString1(serialized1.begin(), serialized1.end());
    cout << printableString1 << endl;
    
    return 0;
}