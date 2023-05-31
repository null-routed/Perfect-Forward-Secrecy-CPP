#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <string>
#include <chrono>
#include <vector>

struct Transfer
{
    std::string sender;
    std::string receiver;
    double amount;
    time_t timestamp;

    friend std::ostream &operator<<(std::ostream &os, const Transfer &transfer); // overloading the << operator for fancy printing
};

struct User
{
    std::string username;
    std::string account_id;
    double balance;
    std::string hashed_password;
    std::vector<Transfer> transfer_history;
};

struct Header
{
    uint32_t length;
    uint32_t sender;
};

struct Message
{
    int command;
    std::chrono::system_clock::time_point timestamp;
    std::string content;
    std::string hmac;
};

#endif
