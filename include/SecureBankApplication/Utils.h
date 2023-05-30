#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include "Transaction.h"

/**
 * @brief The function serializes the struct by building a string with all the
 * parameters of the struct, separated by |
 *
 * @param toSerialize: reference to the Message struct to serialize
 * @return vector<unsigned char>, a byte vector ready to be encrypted or sent to a remote host using sockets
 */
std::string serializeMessage(const Message &toSerialize);

/**
 * @brief The function splits the string on the separator and populates the fields of the message struct
 *
 * @param serialized a byte vector
 * @return Message, a struct build out of the data contained in serialized
 */
Message deserializeMessage(const std::vector<unsigned char> &serialized);

std::vector<char> serializeHeader(const Header& header);

Header deserializeHeader(const char* buffer);

std::string bytes_to_hex(const std::vector<unsigned char> &bytes);
std::vector<unsigned char> hex_to_bytes(const std::string &hex);
unsigned char hex_digit_to_value(char digit);
void exit_with_error(const std::string &error);

void print_vector(const std::vector<unsigned char>& text);

#endif // UTILS_H