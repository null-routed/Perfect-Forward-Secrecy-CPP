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

    // void get_input(const vector<unsigned char>& data);

    void display_options();

    Header create_header(const vector<unsigned char> &message, const vector<unsigned char> &header);

    Message create_message(int option);

    void get_user_details();
};

// Command = login
// nonce =dfadhfauidhfa
// username|password

// is username and passowrd called content?

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