#ifndef CLIENT_H
#define CLIENT_H

#include <vector>
#include "Transaction.h"
// #include "Constants.h"

class Client
{
public:

    Client();

    ~Client();

    // void start_client();

    void connect_with_server();

    void disconnect_with_server();

    // void get_input(const vector<unsigned char>& data);

    void display_options(bool loged_in);

    Header create_header(const std::vector<unsigned char> &message, const std::vector<unsigned char> &header);

    Message create_message(int option);

    void get_user_details();

private:
    X509* ca_cert;
    X509_STORE* cert_store;
};

#endif // CLIENT_H

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