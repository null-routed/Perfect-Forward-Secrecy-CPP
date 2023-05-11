#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <string>

// Struct for a single transfer
struct Transfer
{
    std::string sender;
    std::string receiver;
    uint64_t amount;
    time_t timestamp;

    friend std::ostream &operator<<(std::ostream &os, const Transfer &transfer); // overloading the << operator for fancy printing
};

// Struct for a message. The message will then be serialized and encrypted to 
struct Message
{
    std::string sender; // sender Id
    std::string receiver; // receiver Id
    std::string command; // 
    std::string nonce; // nonce 
    std::string content; // data
    std::string hmac; // hmac(sender, receiver, content, nonce, )
};

#endif
