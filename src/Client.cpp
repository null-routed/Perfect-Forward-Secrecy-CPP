#include "Client.h"
#include "Transaction.h"
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
    cert_store = X509_STORE_new();
    try {
        ca_cert = read_certificate_from_pem() // missing directory
    } catch (runtime_error &e) {
        exit_with_error("Could not read CA's cert");
    }
    if(X509_STORE_add_cert(cert_store, ca_cert) == -1){
        exit_with_error("Could not add certificate to store");
    }
}

Client::~Client()
{
    X509_store_free(cert_store);
}

// Looks good even though valread is never used
Client::connect_with_server()
{   
    int status, valread;
    // Create socket
    int socket = socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0)
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
// Key exchange looks good but needs testing ofc
// The problem here is that the display option should be in a loop
// After the client is connected to the server, we should make a loop where the user is prompted to 
// insert a command and the loop should be repeated until the user uses the CLOSE command
// I would therefore separate the key exchange part in a function and make the rest in another function
Client::handle_server_connection(int socket)
{   
    vector<unsigned char> in_buff;
    vector<unsigned char> out_buff;

    string out_msg_string;
    Message out_msg;

    string in_msg_string;
    Message in_msg;
    Header in_msg_header;

    // string session_id;
    Session session;

    // send client_hello
    out_msg.command = Constants::CLIENT_HELLO;
    out_msg.content = Crypto::generateNonce(Constants::NONCE_LENGTH);
    out_msg_string = serialize_message(out_msg);
    out_buff(out_msg_string.begin(), out_msg_string.end());
    send_with_header(socket, out_buff, 0);

    // receiv server hello
    recv_with_header(socket, in_buff, in_msg_header);
    in_msg_string = string(in_buff.begin(), in_buff.end());
    in_msg = deserialize_message(in_msg_string)
    size_t pos = in_msg.content.find('-');
    vector<unsigned char> eph_pub_key = hex_to_bytes(in_msg.content.substr(0, pos));
    vector<unsigned char> signature = hex_to_bytes(in_msg.content.substr(pos + 1)); // <R || TpubK> 
    vector<unsigned char> cert_vector = hex_to_bytes(in_msg.content.substr(pos + 2));
    X509* cert = deserialize_certificate(cert_vector);
    // Extract public key from certificate
    vector<unsigned char> server_pub_key = Crypto::read_public_key_from_cert(cert);

    // Verify that certificate is valid 
        // Signature of the certificate must be the one of the certification authority
        // Certificate is not expired
        // Certificate belogns to the server owner == 127.0.0.1:8080
    if(!verify_signature(in_msg_string, signature, server_pub_key) || !verify_certificate(cert_store, cert) || read_owner_from_cert(cert) != Constants::EXPECTED_CERT_OWNER) 
    {
        exit_with_error("[-] Error");
    }

    // Generate HMAC key and AES key
    session.hmac_key = generateNonce(Constants::HMAC_LENGTH);
    session.aes_key = generateNonce(Constants::AES_LENGTH);
    out_msg.command = Constants::KEY_EXCHANGE;
    out_msg.nonce = generateNonce(Constants::NONCE_LENGTH);
    out_msg.content = bytes_to_hex(session.hmac_key) + '-' + bytes_to_hex(session.aes_key);
    if(rsa_encrypt(eph_pub_key, serialize_message(out_msg), out_buff)==-1)
    {
        exit_with_error("[-]Error failed to encrypt key exchange message");
    }
    // Key exchange
    send_with_header(socket, out_buff, 0);

    // receiv server OK
    recv_with_header(socket, in_buff, in_msg_header);
    // decrypt with aes_key
    if(Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1) {
        cout << "[-] Key exchange failed: Can't decrypt session id" << endl; 
        return
    }
    in_msg = deserialize_message(in_msg_string);
    if (in_msg.command != Constants::SERVER_OK)
    {
        in_msg.content.clear();
        cout << "[-] Key exchange failed: wrong command" << endl; 
        return
    }
    session.session_id = in_msg.content;

    

    int option;
    Client::display_options(loged_in);
    std::cout << "Enter the option number: ";
    std::cin >> option;

    switch (option)
    {

        case Constants::LOGIN:
            if (loged_in)
            {
                std::cout << "Invalid option selected." << std::endl;
                break;
            }
            // get username and password
            std::cout << "Enter username: ";
            std::cin >> session.username;

            std::cout << "Enter password: ";
            std::cin >> session.password;
            out_msg.command = Constants::LOGIN;
            out_msg.timestamp = chrono::steady_clock::now();
            out_msg.content = session.username + '|' + session.password;
            if(!Crypto::generateHMAC(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            Crypto::aes_encrypt(session.aes_key, serialize_message(out_msg), out_buff);
            send_with_header(new_socket, out_buff, session_id);

            // Receiv server response
            recv_with_header(socket, in_buff, in_msg_header);
            if(Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1) {
                cout << "[-] Key exchange failed: Can't decrypt session id" << endl; 
                return
            }
            in_msg = deserialize_message(in_msg_string);
            if (in_msg.command != Constants::SUCCESS)
            {
                in_msg.content.clear();
                cout << "[-] Failed to login" << endl; 
                return
            }else{
                loged_in = true;
            }
            break;

        case Constants::TRANSFER:

            break;

        case Constants::GET_BALANCE:
        {
            std::vector<unsigned char> key;
            std::vector<unsigned char> content;
            std::vector<unsigned char> hmac;

            vector<unsigned char> nonce = Crypto::generateNonce(Constants::NONCE_LENGTH);

            // Crypto::generateHMAC(key, content, hmac);

            Message message = Client::create_message(Constants::GET_BALANCE);
            Header header = Client::create_header(message, sender);
            // send header
            // send message
            // receiv balance
        }
            break;

        case Constants::GET_TRANSFER_HISTORY:
            
            break;

        default:
            std::cout << "Invalid option selected." << std::endl;
    }
}

// Can be removed since the client hello message is already built in the previous 
// Function. Otherwise we must modify the previous function
Client::client_hello()
{
    Message hello_msg;
    hello_mng.command = Constants::CLIENT_HELLO;
    hello_mng.content = "R";
    
}

// Probably not needed since we can use send_with_header that builds the header automatically
Client::create_header(const Message &toSerialize, uint32_t sender)
{
    Header header;
    vector<unsigned char> serialized_message = serialize_message(const Message &toSerialize);
    header.length = serialize_message.size();
    header.sender = sender;
    return header;
}

// Probably not needed
Client::create_message(int option, const vector<unsigned char> &header, uint32_t sender)
{
    Message message;
    message.option = option;
    message.nonce = Crypto::generateNonce(Constants::NONCE_LENGTH);
    // message.content = What is content when we ask for balance
    // message.hmac = Crypto::generateHMAC(); option, nonce and message as content?
    return message;
}

// Looks good, but I would also add a 5th option "CLOSE"
Client::display_options(bool loged_in) {
    std::cout << "Choose one of the options:" << std::endl;
    if (loged_in)
    {
        // std::cout << "0. Create account" << std::endl;
        std::cout << "1. Log in" << std::endl;
    }
    std::cout << "2. Make transfer" << std::endl;
    std::cout << "3. Check balance" << std::endl;
    std::cout << "4. Show history of transfers" << std::endl;
}

// Looks good 
Client::get_transfer_details(string sender)
{
    Transfer transfer;
    trnsfer.amount = 0.0;
    transfer.sender = sender;
    std::cout << "Specify recipient:" << std::endl;
    std::cin >> transfer.receiver;

    while(transfer.amount <= 0.0)
    {
        std::cout << "Specify amount:" << std::endl;
        std::cin >> transfer.amount;
    }
    
    transfer.timestamp = std::time(0);

    return transfer;
}