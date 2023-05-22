#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>
#include <cstring>
#include "../src/Crypto.cpp"
#include "../src/Utils.cpp"
#include "../src/Transaction.cpp"
using namespace std; 

int main() {
    const string file_path = "userdata.txt";
    const unsigned char enc_key_arr[] = { 0x01, 0x02, 0x03, 0x04 };
    const std::vector<unsigned char> enc_key(enc_key_arr, enc_key_arr + sizeof(enc_key_arr) / sizeof(enc_key_arr[0]));

    // Create example user data
    User user_data;
    user_data.username = "John";
    user_data.account_id = "A12345";
    user_data.balance = 1000.50;
    user_data.hashed_password = "1a2b3c4d5e";

    Transfer transfer1;
    transfer1.sender = "Alice";
    transfer1.receiver = "Bob";
    transfer1.amount = 500.25;
    transfer1.timestamp = time(nullptr);

    Transfer transfer2;
    transfer2.sender = "Eve";
    transfer2.receiver = "John";
    transfer2.amount = 250.75;
    transfer2.timestamp = time(nullptr);

    user_data.transfer_history.push_back(transfer1);
    user_data.transfer_history.push_back(transfer2);

    // Write user data to file
    write_user_data(file_path, user_data, enc_key);
    cout << "User data written to file." << endl;

    // Load user data from file
    User loaded_user_data = load_user_data(file_path, enc_key);
    cout << "Loaded user data:" << endl;
    cout << "Username: " << loaded_user_data.username << endl;
    cout << "Account ID: " << loaded_user_data.account_id << endl;
    cout << "Balance: " << loaded_user_data.balance << endl;
    cout << "Hashed Password: " << loaded_user_data.hashed_password << endl;

    cout << "Transfer History:" << endl;
    for (const Transfer& transfer : loaded_user_data.transfer_history) {
        cout << transfer << endl;
    }

    return 0;
}