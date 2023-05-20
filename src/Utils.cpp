#pragma once

#include <string>
#include <iostream>
#include <cstring>
#include <sstream>
#include <vector>
#include "../include/SecureBankApplication/Utils.h"
#include "../include/SecureBankApplication/Transaction.h"

using namespace std;

string serialize_message(const Message &toSerialize)
{
    string sm = to_string(toSerialize.command) + "|" + toSerialize.nonce + "|" + toSerialize.content + "|" + toSerialize.hmac;
    return sm;
}

Message deserialize_message(const string &serialized)
{
    Message msg;

    stringstream ss(serialized);

    string command;
    getline(ss, command, '|');
    msg.command = stoi(command);

    getline(ss, msg.nonce, '|');
    getline(ss, msg.content, '|');
    getline(ss, msg.hmac, '|');

    return msg;
}

vector<unsigned char> serialize_header(Header header) 
{
    header.length = htonl(header.length);
    header.sender = htonl(header.sender)
    vector<char> serialized(sizeof(Header));
    memcpy(serialized.data(), &header, sizeof(Header));

    return serialized;
}

Header deserialize_header(const unsigned char* buffer) {
    Header header;
    memcpy(&header, buffer, sizeof(header));
    header.length = ntohl(header.length);
    header.sender = ntohl(header.sender);
    return header;
}

string bytes_to_hex(const vector<unsigned char> &bytes)
{
    string hex;
    hex.reserve(bytes.size() * 2);
    const char *hex_digits = "0123456789ABCDEF";
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        unsigned char byte = bytes[i];
        // Shifting the byte of 4 positions to encode the 4 most significant bits
        hex.push_back(hex_digits[byte >> 4]);
        // Masking the byte with 15 (0x0F) to encode the 4 least significant bits
        hex.push_back(hex_digits[byte & 15]);
    }
    return hex;
}

vector<unsigned char> hex_to_bytes(const string &hex)
{
    vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        // Using two hex char to build a byte
        unsigned char byte = (hex_digit_to_value(hex[i]) << 4) | hex_digit_to_value(hex[i + 1]);
        bytes.push_back(byte);
    }
    return bytes;
}

unsigned char hex_digit_to_value(char digit)
{
    if ('0' <= digit && digit <= '9')
        return digit - '0';
    else
        return 10 + (digit - 'A');
}

void exit_with_error(const string &error)
{
    cerr << error << endl;
    exit(1);
}

void print_vector(vector<unsigned char>& text)
{
    for (unsigned char c : text) {
        std::cout << c;
    }
    std::cout << std::endl;
}