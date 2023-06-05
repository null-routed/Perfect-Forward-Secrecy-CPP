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

    /**
     * @brief Creates connesction with server
     * 
     */
    void connect_with_server();
    
    /**
     * @brief Handles connection with server
     * 
     */
    void handle_server_connection();

    /**
     * @brief Performs the handshake protocol with the server and populates the session struct
     * 
     */
    void get_session(int verbose);

    /**
     * @brief Disconects from server
     * 
     */
    void disconnect_with_server();

    /**
     * @brief Displays options avaiable for user
     * 
     * @param loged_in 
     */
    void display_options(bool loged_in);

    /**
     * @brief Get the user details object
     * 
     */
    void get_user_details();

    /**
     * @brief Destroys session keys
     * 
     */
    void destroy_session_keys();

    /**
     * @brief Veryfies if incoming message in authentic
     * 
     * @param client_socket 
     * @param in_buff 
     * @param in_msg_header 
     * @param out_msg 
     * @param in_msg 
     * @return true 
     * @return false 
     */
    bool verify_msg_authenticity(int client_socket, std::vector<unsigned char> &in_buff, Header &in_msg_header, Message &out_msg, Message &in_msg);

    /**
     * @brief Handles login option
     * 
     * @param logged_in 
     * @param in_buff 
     * @param out_buff 
     * @param in_msg_header 
     * @param out_msg 
     * @param in_msg 
     * @param in_msg_string 
     * @param out_msg_string 
     */
    bool handle_login(std::vector<unsigned char> &in_buff, std::vector<unsigned char> &out_buff, Header &in_msg_header, Message &out_msg, Message &in_msg, std::string &out_msg_string);

    /**
     * @brief Handles transfer option
     * 
     * @param transfer 
     * @param in_buff 
     * @param out_buff 
     * @param in_msg_header 
     * @param out_msg 
     * @param in_msg 
     * @param in_msg_string 
     * @param out_msg_string 
     */
    void handle_transfer(Transfer transfer, std::vector<unsigned char> &in_buff, std::vector<unsigned char> &out_buff, Header &in_msg_header, Message &out_msg, Message &in_msg, std::string &out_msg_string);

    /**
     * @brief Handles get balance option
     * 
     * @param in_buff 
     * @param out_buff 
     * @param in_msg_header 
     * @param out_msg 
     * @param in_msg 
     * @param in_msg_string 
     * @param out_msg_string 
     */
    void handle_get_balance(std::vector<unsigned char> &in_buff, std::vector<unsigned char> &out_buff, Header &in_msg_header, Message &out_msg, Message &in_msg, std::string &out_msg_string);
    
    /**
     * @brief Handles get transfer history
     * 
     * @param in_buff 
     * @param out_buff 
     * @param in_msg_header 
     * @param out_msg 
     * @param in_msg 
     * @param in_msg_string 
     * @param out_msg_string 
     */
    void handle_get_transfer_history(Transfer transfer, std::vector<unsigned char> &in_buff, std::vector<unsigned char> &out_buff, Header &in_msg_header, Message &out_msg, Message &in_msg, std::string &out_msg_string);

    /**
     * @brief Handles close option
     * 
     * @param in_buff 
     * @param out_buff 
     * @param in_msg_header 
     * @param out_msg 
     * @param in_msg 
     * @param in_msg_string 
     * @param out_msg_string 
     */
    void handle_close(std::vector<unsigned char> &in_buff, std::vector<unsigned char> &out_buff, Header &in_msg_header, Message &out_msg, Message &in_msg, std::string &out_msg_string);

private:
    X509* ca_cert;
    X509_STORE* cert_store;
    Session session;
    bool logged_in = false;
    int client_socket;
};

#endif // CLIENT_H
