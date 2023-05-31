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
    std::string session_id;
    std::string username;
    std::string password;
};

class Client
{
public:

    Client();

    ~Client();

    void connect_with_server();

    void handle_server_connection();

    void get_session(int socket);

    void disconnect_with_server();

    void display_options(bool loged_in);

    void get_user_details();

    void destroy_session_keys();

private:

    X509* ca_cert;
    X509_STORE* cert_store;
    Session session;
    int socket;
};

#endif // CLIENT_H
