#ifndef CLIENT_H
#define CLIENT_H

#include <vector>

class Client
{
public:

    void Client();

    void ~Client();

    // void start_client();

    void connect_with_server();

    void disconnect_with_server();

    void send_message();

    void receiv_message();

    void get_input(const vector<unsigned char> &key);

    int length_of_message(const vector<unsigned char> &message);

    void create_header();

    void concatenate_message_and_header(const vector<unsigned char> &header, const vector<unsigned char> &message);
};

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