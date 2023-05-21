#include "../include/SecureBankApplication/Client.h"
#include "../include/SecureBankApplication/Transaction.h"
#include "Utils.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <iostream> 
#include <vector>
#include <string>

using namespace std;

Client::Client()
{

}

Client::~Client()
{
    
}

Client::connect_with_server()
{   
    int status, valread;
    // Create socket
    int s0 = socket(AF_INET, SOCK_STREAM, 0);
    if (s0 < 0)
    {   
        exit_with_error("[-] Error: failed to create clients socket\n");
    }
 
    // Fill in server IP address
    struct sockaddr_in server_addres;
    memset(&server_addres, 0, sizeof(server_addres));

    server_addres.sin_family = AF_INET;
    server_addres.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addres.sin_addr) <= 0)
    {
        exit_with_error("[-] Error: invalid address/ Address not supported \n")
    }

    if ((status = connect(client_fd, (struct sockaddr*)&server_addres, sizeof(server_addres))) < 0) {
        exit_with_error("[-] Error: Connection Failed \n");
    }
}

// Client::get_input(std::vector<unsigned char>& data)
// {
//     std::string input;
//     std::cin >> input;

//     // Clear the vector before reading new input
//     inputVector.clear();

//     // Convert each character of the input string to unsigned char
//     for (char c : input) {
//         data.push_back(static_cast<unsigned char>(c));
//     }
// }

Client::create_header(const Message &toSerialize, uint32_t sender)
{
    Header header;
    vector<unsigned char> serialized_message = serialize_message(const Message &toSerialize);
    header.length = serialize_message.size();
    header.sender = sender;
    return header;
}

Client::create_message(int option, const vector<unsigned char> &header, uint32_t sender)
{
    int nonce_length = 16; //???
    Message message;
    message.option = option;
    message.nonce = Crypto::generateNonce(nonce_length);
    // message.content = What is content when we ask for balance
    // message.hmac = Crypto::generateHMAC(); option, nonce and message as content?
    return message;
}

Client::display_options(bool loged_in) {
    std::cout << "Choose one of the options:" << std::endl;
    if (loged_in)
    {
        std::cout << "0. Create account" << std::endl;
        std::cout << "1. Log in" << std::endl;
    }
    std::cout << "2. Make transfer" << std::endl;
    std::cout << "3. Check balance" << std::endl;
    std::cout << "4. Show history of transfers" << std::endl;
}