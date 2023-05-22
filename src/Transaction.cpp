#include <iostream>
#include <string>
#include <ctime>
#include "../include/SecureBankApplication/Transaction.h"

using namespace std;

std::ostream& operator<<(std::ostream& os, const Transfer& transfer) {
    std::string timestampStr = std::asctime(std::localtime(&transfer.timestamp));
    timestampStr = timestampStr.substr(0, timestampStr.length() - 1);  // Remove the trailing newline character

    // Print the transfer information in a fancy format
    os << "Sender: " << transfer.sender << std::endl;
    os << "Receiver: " << transfer.receiver << std::endl;
    os << "Amount: " << transfer.amount << std::endl;
    os << "Timestamp: " << timestampStr;

    return os;
}