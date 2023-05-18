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

struct Header {
    uint32_t length;    
    uint32_t sender;   
};

struct Message
{
    int command; 
    std::string nonce;
    std::string content;
    std::string hmac; 
};

#endif
