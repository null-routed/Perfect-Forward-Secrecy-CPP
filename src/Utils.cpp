#pragma once

#include <sys/socket.h>
#include <string>
#include <iostream>
#include <cstring>
#include <sstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <fstream>
#include <stdexcept>
#include <stdio.h>
#include "../include/SecureBankApplication/Utils.h"
#include "../include/SecureBankApplication/Transaction.h"

using namespace std;

vector<unsigned char> read_private_key_from_pem(const string &file_path)
{
    ifstream file(file_path);
    string priv_key_str((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return vector<unsigned char>(priv_key_str.begin(), priv_key_str.end());
}

X509 *read_certificate_from_pem(const string &file_path)
{
    FILE *fp = fopen(file_path.c_str(), "r");
    if (!fp)
    {
        throw runtime_error("Failed to open certificate file");
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert)
    {
        throw runtime_error("Failed to read certificate");
    }

    return cert;
}

vector<unsigned char> serialize_certificate(X509 *cert)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    char *data;
    long len = BIO_get_mem_data(bio, &data);

    vector<unsigned char> serialized(data, data + len);

    BIO_free(bio);

    return serialized;
}

X509 *deserialize_certificate(const vector<unsigned char> &serialized)
{
    BIO *bio = BIO_new_mem_buf(serialized.data(), (int)serialized.size());

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);

    if (!cert)
    {
        throw runtime_error("Failed to deserialize certificate");
    }

    return cert;
}

string serialize_transfer(const Transfer &transfer)
{
    string st = transfer.sender + "|" + transfer.receiver + "|" + to_string(transfer.amount) + "|" + to_string(transfer.timestamp);
    return st;
}

string serialize_message_for_hmac(const Message &toSerialize)
{
    string sm = to_string(toSerialize.command) + "|" + toSerialize.nonce + "|" + toSerialize.content;
    return sm;
}

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
    header.sender = htonl(header.sender);
    vector<unsigned char> serialized(sizeof(Header));
    memcpy(serialized.data(), &header, sizeof(Header));

    return serialized;
}

Header deserialize_header(const unsigned char *buffer)
{
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
    perror(error.c_str());
    exit(1);
}

void print_vector(vector<unsigned char> &text)
{
    for (unsigned char c : text)
    {
        cout << c;
    }
    cout << endl;
}

void write_user_data(const string& file_path, const User& user_data, const vector<unsigned char> &enc_key) {
    ofstream file(file_path);
    vector<unsigned char> enc_buffer; 
    if (file.is_open()) {
        file << user_data.username << '|'
             << user_data.account_id << '|'
             << to_string(user_data.balance) << '|'
             << user_data.hashed_password << "\n";

        for (const Transfer& transfer : user_data.transfer_history) {
            string serialized_transfer = serialize_transfer(transfer);
            Crypto::aes_encrypt(enc_key, serialized_transfer, enc_buffer);
            file << bytes_to_hex(enc_buffer) << "\n";
        }

        file.close();
    } else {
        throw runtime_error("Failed to open path" + file_path);
    }
}

User load_user_data(const string& file_path, const vector<unsigned char> &enc_key) {
    ifstream file(file_path);
    User user_data;

    if (file.is_open()) {
        string line;
        if (getline(file, line)) {
            stringstream ss(line);
            getline(ss, user_data.username, '|');
            getline(ss, user_data.account_id, '|');
            ss >> user_data.balance;
            ss.ignore();
            getline(ss, user_data.hashed_password);

            string enc_transfer_data;
            while (getline(file, enc_transfer_data)) {
                string transfer_data;
                Crypto::aes_decrypt(enc_key, hex_to_bytes(enc_transfer_data), transfer_data);
                stringstream ts(transfer_data);
                Transfer transfer;
                getline(ts, transfer.sender, '|');
                getline(ts, transfer.receiver, '|');
                ts >> transfer.amount;
                ts.ignore();
                ts >> transfer.timestamp;
                user_data.transfer_history.push_back(transfer);
                transfer_data.clear();
            }
        }
        file.close();
    } else {
        throw runtime_error("Failed to open user file:" + file_path);
    }

    return user_data;
}

int send_with_header(int socket, const vector<unsigned char> &data_buffer, uint32_t sender)
{
    Header header;
    header.length = data_buffer.size();
    header.sender = sender;
    vector<unsigned char> header_buffer = serialize_header(header);

    int ret = send(socket, header_buffer.data(), header_buffer.size(), 0);
    if (ret <= 0)
    {
        return -1;
    }

    ret = send(socket, data_buffer.data(), data_buffer.size(), 0);
    if (ret <= 0)
    {
        return -1;
    }

    return ret;
}

int recv_with_header(int socket, vector<unsigned char> &data_buffer, Header &header)
{
    vector<unsigned char> header_buffer(Constants::HEADER_SIZE);
    int ret = recv(socket, header_buffer.data(), Constants::HEADER_SIZE, 0);
    if (ret <= 0)
    {
        return -1;
    }

    header = deserialize_header(header_buffer.data());

    data_buffer.resize(header.length);
    vector<unsigned char> tmp_buffer(Constants::MAX_BUFFER_SIZE);
    int recv_data = 0;

    while (recv_data < header.length)
    {
        ret = recv(socket, tmp_buffer.data(), Constants::MAX_BUFFER_SIZE, 0);
        if (ret <= 0)
        {
            return -1;
        }
        recv_data += ret;
        copy(tmp_buffer.begin(), tmp_buffer.begin() + ret, data_buffer.begin() + recv_data - ret);
    }

    return recv_data;
}