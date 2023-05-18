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

// Command = login
// nonce =dfadhfauidhfa
// username|password

// hmac(login-dfadhfauidhfa-username|password)
// enc(hmac)

// sender = session_id
// length = length(enc)

// send header
// send message

// Client:
// command = CLIENT_HELLO
// nonce = None
// content = R

// Server:
// command = SERVER_HELLO
// nonce = None
// content = TempPubK, Sign(<R || TempPubK, privK), Certificate

