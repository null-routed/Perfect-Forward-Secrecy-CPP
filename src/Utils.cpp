#include <string>
#include <iostream>
#include <cstring>
#include <sstream>
#include "../include/SecureBankApplication/Transaction.h"

using namespace std;

/**
 * @brief The function serializes the struct by building a string with all the
 * parameters of the struct, separated by |
 * 
 * Warning: the serializedMessage must be deleted, as this function uses new
 * @param toSerialize: reference to the Message struct to serialize
 * @return unsigned char*, a byte buffer ready to be encrypted or sent to a remote host using sockets
 */
unsigned char *serializeMessage(const Message &toSerialize)
{
    string sm = toSerialize.sender + "|" + toSerialize.receiver + "|" + to_string(toSerialize.command) + "|" + toSerialize.nonce + "|" + toSerialize.content + "|" + toSerialize.hmac;
    unsigned char *serializedMessage = new unsigned char[sm.size() + 1];
    strcpy(reinterpret_cast<char *>(serializedMessage), sm.c_str());
    return serializedMessage;
}

/**
 * @brief The function splits the string on the separator and populates the fields of the message struct
 * 
 * @param serialized a pointer to a byte buffer (unsigned char)
 * @return Message, a struct build out of the data contained in serialized
 */
Message deserializeMessage(const unsigned char *serialized)
{
    Message msg;
    string temp(serialized, serialized + strlen(reinterpret_cast<const char*>(serialized)));

    stringstream ss(temp);

    getline(ss, msg.sender, '|');
    getline(ss, msg.receiver, '|');

    string command;
    getline(ss, command, '|');
    msg.command = std::stoi(command);

    getline(ss, msg.nonce, '|');
    getline(ss, msg.content, '|');
    getline(ss, msg.hmac, '|');

    return msg;
}

void exitWithError(const std::string &error)
{
    std::cerr << error << std::endl;
    exit(1);
}
