#include <string>
#include <iostream>
#include <cstring>
#include <sstream>
#include <vector>
#include "../include/SecureBankApplication/Transaction.h"

using namespace std;

/**
 * @brief The function serializes the struct by building a string with all the
 * parameters of the struct, separated by |
 *
 * @param toSerialize: reference to the Message struct to serialize
 * @return vector<unsigned char>, a byte vector ready to be encrypted or sent to a remote host using sockets
 */
string serializeMessage(const Message &toSerialize)
{
    string sm = toSerialize.sender + "|" + toSerialize.receiver + "|" + to_string(toSerialize.command) + "|" + toSerialize.nonce + "|" + toSerialize.content + "|" + toSerialize.hmac;
    return sm;
}

/**
 * @brief The function splits the string on the separator and populates the fields of the message struct
 *
 * @param serialized a byte vector
 * @return Message, a struct build out of the data contained in serialized
 */
Message deserializeMessage(const string &serialized)
{
    Message msg;

    stringstream ss(serialized);

    getline(ss, msg.sender, '|');
    getline(ss, msg.receiver, '|');

    string command;
    getline(ss, command, '|');
    msg.command = stoi(command);

    getline(ss, msg.nonce, '|');
    getline(ss, msg.content, '|');
    getline(ss, msg.hmac, '|');

    return msg;
}

void exitWithError(const string &error)
{
    cerr << error << endl;
    exit(1);
}

