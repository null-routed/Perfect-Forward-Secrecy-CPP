#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <sys/socket.h>
#include <openssl/x509.h>
#include "Transaction.h"
/**
* @brief Reads a private key from a PEM file
* @param file_path Path to the PEM file
* @return Vector of bytes representing the private key
*/
std::vector<unsigned char> read_private_key_from_pem(const std::string &file_path);

/**
* @brief Reads a certificate from a PEM file
* @param file_path Path to the PEM file
* @return X509 certificate
*/
X509 *read_certificate_from_pem(const std::string &file_path);

/**
* @brief Serializes an X509 certificate
* @param cert X509 certificate to serialize
* @return Vector of bytes representing the serialized certificate
*/
std::vector<unsigned char> serialize_certificate(X509 *cert);

/**
* @brief Deserializes an X509 certificate
* @param serialized Vector of bytes representing the serialized certificate
* @return X509 certificate
*/
X509 *deserialize_certificate(const std::vector<unsigned char> &serialized);

/**
* @brief Serializes a Transfer object to a string
* @param transfer Transfer object to serialize
* @return Serialized string
*/
std::string serialize_transfer(const Transfer &transfer);

/**
* @brief Deserializes string to Transfer object
* @param Serialized string
* @return transfer Transfer object to serialize
*/
Transfer deserialize_transfer(const std::string &serialized);

/**
* @brief Serializes a Message object for HMAC
* @param toSerialize Message object to serialize
* @return Serialized string
*/
std::string serialize_message_for_hmac(const Message &toSerialize);

/**
* @brief Serializes a Message object
* @param toSerialize Message object to serialize
* @return Serialized string
*/
std::string serialize_message(const Message &toSerialize);

/**
* @brief Deserializes a Message object from a string
* @param serialized Serialized string
* @return Deserialized Message object
*/
Message deserialize_message(const std::string &serialized);

/**
* @brief Serialize a Header object to a vector of bytes
* @param header Header object to serialize
* @return Vector of bytes representing the serialized Header
*/
std::vector<unsigned char> serialize_header(Header header);

/**
* @brief Deserializes a Header object from a buffer
* @param buffer Buffer containing the serialized Header
* @return Deserialized Header object
*/
Header deserialize_header(const unsigned char *buffer);

/**
* @brief Sends message with header
* @param socket socket
* @param data_bufer bufer variable with data
* @param sender number of sender
* @return amount of bytes that were sent, -1 on error
*/
int send_with_header(int socket, const std::vector<unsigned char> &data_buffer, uint32_t sender);

/**
 * @brief receives a message with its corresponding header
 * 
 * @param socket 
 * @param data_buffer 
 * @param header 
 * @return amount of bytes that were received, -1 on error
 */
int recv_with_header(int socket, std::vector<unsigned char> &data_buffer, Header &header);

/**
* @brief Converst a vector of bytes to a hexadecimal string
* @param bytes Vector of bytes to convert
* @return Hexadecimal string
*/
std::string bytes_to_hex(const std::vector<unsigned char> &bytes);

/**
* @brief Converts a hexadecimal string to a vector of bytes
* @param hex Hexadecimal string to convert
* @return Vector of bytes
*/
std::vector<unsigned char> hex_to_bytes(const std::string &hex);

/**
* @brief Converts a hexadecimal digit to its value
* @param digit Hexadecimal digit to convert
* @return Value of the hexadecimal digit
*/
unsigned char hex_digit_to_value(char digit);

/**
* @brief Exits the program with an error message
* @param error Error message
*/
void exit_with_error(const std::string &error);

/**
* @brief Prints a vector of bytes to the console
* @param text Vector of bytes to print
*/
void print_vector(std::vector<unsigned char> &text);

void write_user_data(const std::string& file_path, const User& user_data, const std::vector<unsigned char> &enc_key);

User load_user_data(const std::string& file_path, const std::vector<unsigned char> &enc_key);

#endif // UTILS_H