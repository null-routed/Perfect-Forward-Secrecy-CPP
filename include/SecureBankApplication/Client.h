#ifndef CLIENT_H
#define CLIENT_H

#include <vector>
#include "Transaction.h"
#include <openssl/x509.h>
// #include "Constants.h"

struct Session
{
    std::vector<unsigned char> hmac_key;
    std::vector<unsigned char> aes_key;
    uint32_t session_id;
    std::string username;
};

class Client
{
public:

    Client();

    ~Client();

    void connect_with_server();

    void handle_server_connection();

    void get_session();

    void disconnect_with_server();

    void display_options(bool loged_in);

    void get_user_details();

    void destroy_session_keys();

    bool verify_msg_authenticity(int client_socket, std::vector<unsigned char> &in_buff, Header &in_msg_header, Message &out_msg, Message &in_msg);

private:

    X509* ca_cert;
    X509_STORE* cert_store;
    Session session;
    int client_socket;
};

#endif // CLIENT_H
