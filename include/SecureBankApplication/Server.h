#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <unordered_map>
#include <vector>
#include "Transaction.h"
#include <openssl/hmac.h>
#include <openssl/aes.h>

// User data structure
struct User
{
    std::string username;
    std::string accountId;
    double balance;
    std::string hashedPassword;
    std::vector<Transfer> transferHistory;
};

struct Session {
    unsigned char hmacSessionKey[EVP_MD_size(EVP_sha256())]; // assuming we use sha256 for the hmac
    unsigned char aesSessionKey[AES_BLOCK_SIZE]; // array to store the session key for encryption
    // maybe something more?
    std::vector<std::string>> sessionNonces;
};

// Class for the bank server
class Server
{
public:
    Server();  // constructor
    ~Server(); // destructor, maybe not even necessary

    // Function to start the server
    // The server starts the websocket server and starts listening for clients to serve
    void startServer();

    // Function to handle a client connection
    void handleClientConnection(int clientSocket);

    // Function to load user data from a file
    // The idea behind this is: Client requests something, Server populates a User structure with all the necessary data of that user
    User loadUserData(const std::string &filename);

    // Function to save user data to a file
    void saveUserData(const std::string &filename);

    // Function to authenticate a user
    // This function loads the user data, verifies the hashed password is the same as the one we stored (invoking the function in Crypto.h), 
    // returns a bool
    bool authenticateUser(const std::string &username, const std::string &password);

    // Function to execute a transfer
    // This function loads both the sender's and the receiver's user data, verifies the sender can actually send the money
    // If the sender has the money, it updates the balances and saves everything on file using saveUserData
    bool executeTransfer(const std::string &fromUser, const std::string &toUser, double amount);

    // Function to get a user's transfer history
    std::vector<Transfer> getTransferHistory(const std::string &username);

private:
    // Using a map to store sessions
    // we store a sessions indexed by (just like in python dicts)
    std::unordered_map<std::string, Session> sessions;
};

#endif // SERVER_H
