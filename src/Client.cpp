#include "Client.h"
#include "Transaction.h"
#include "Constants.h"
#include "Utils.h"
#include "Crypto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <iostream>
#include <vector>
#include <string>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <sstream>
#include <chrono>

using namespace std;
using namespace Constants;

Client::Client()
{
    cert_store = X509_STORE_new();
    try
    {
        ca_cert = read_certificate_from_pem(string(CERT_PATH) + "ca_cert.pem"); // missing directory
    }
    catch (runtime_error &e)
    {
        exit_with_error("Could not read CA's cert");
    }
    if (X509_STORE_add_cert(cert_store, ca_cert) == -1)
    {
        exit_with_error("Could not add certificate to store");
    }
}

Client::~Client()
{
    X509_STORE_free(cert_store);
}

// Looks good even though valread is never used
void Client::connect_with_server()
{
    int status;
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0)
    {
        exit_with_error("[-] Error: failed to create clients socket\n");
    }

    // Fill in server IP address
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0)
    {
        exit_with_error("[-] Error: invalid address/ Address not supported \n");
    }

    // Connect with server
    if ((status = connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address))) < 0)
    {
        exit_with_error("[-] Error: Connection Failed \n");
    }
    cout << "conected" << endl;
}

void Client::destroy_session_keys()
{
    memset(session.aes_key.data(), 0, session.aes_key.size());
    memset(session.hmac_key.data(), 0, session.hmac_key.size());
}

void Client::handle_server_connection()
{
    vector<unsigned char> in_buff;
    vector<unsigned char> out_buff;

    string out_msg_string;
    Message out_msg;

    string in_msg_string;
    Message in_msg;
    Header in_msg_header;

    Session session;
    Transfer transfer;
    bool logged_in = false;

    // Start session with server
    Client::get_session();

    int option = -1;

    while (option != CLOSE)

    {
        Client::display_options(logged_in);
        cout << "Enter the option number: ";
        cin >> option;
        option += 3; 
        switch (option)
        {
        case LOGIN:
            if (logged_in)
            {
                cout << "Invalid option selected." << endl;
                break;
            }

            // get username and password
            cout << "Enter username: ";
            cin >> session.username;

            cout << "Enter password: ";
            cin >> session.password;
            out_msg.command = LOGIN;
            out_msg.content = session.username + '|' + session.password;
            out_msg.timestamp = chrono::system_clock::now();

            // generate HMAC for login message
            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            out_msg_string = serialize_message(out_msg);
            Crypto::aes_encrypt(session.aes_key, out_msg_string, out_buff);
            send_with_header(client_socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(client_socket, in_buff, in_msg_header);

            // Decrypt message with AES key
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Key exchange failed: Can't decrypt session id" << endl;
                exit_with_error("[-] Error: failed to decrypt session id");
            }

            // create message
            in_msg = deserialize_message(in_msg_string);

            // Verify if HMAC of received message is correct
            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)))
            {
                cout << "[-] Received message with wrong HMAC" << endl;
            }

            if (in_msg.command != SUCCESS)
            {
                in_msg.content.clear();
                cout << "[-] Failed to login" << endl;
            }
            else
            {
                logged_in = true;
            }
            break;

        case TRANSFER:
            transfer.amount = 0.0;
            cout << "Enter username of receiver: ";
            cin >> transfer.receiver;

            // Make sure User can't send amount smaller than 0
            while (transfer.amount <= 0.0)
            {
                cout << "Specify amount:" << endl;
                cin >> transfer.amount;
            }

            out_msg.command = TRANSFER;
            out_msg.content = transfer.receiver + '-' + to_string(transfer.amount);
            out_msg.timestamp = chrono::system_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            out_msg_string = serialize_message(out_msg);
            Crypto::aes_encrypt(session.aes_key, out_msg_string, out_buff);
            send_with_header(client_socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(client_socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }

            in_msg = deserialize_message(in_msg_string);
            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)))
            {
                cout << "[-] Received message with wrong HMAC" << endl;
            }

            if (in_msg.command != SUCCESS)
            {
                in_msg.content.clear();
                cout << "[-] Failed to transfer money" << endl;
            }

            break;

        case GET_BALANCE:
            out_msg.command = GET_BALANCE;
            out_msg.timestamp = chrono::system_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            out_msg_string = serialize_message(out_msg);
            Crypto::aes_encrypt(session.aes_key, out_msg_string, out_buff);
            send_with_header(client_socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(client_socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }
            in_msg = deserialize_message(in_msg_string);

            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)))
            {
                cout << "[-] Received message with wrong HMAC" << endl;
            }

            if (in_msg.command != SUCCESS)
            {
                in_msg.content.clear();
                cout << "[-] Failed to get balance" << endl;
            }
            else
            {
                cout << in_msg.content << endl;
            }
            break;

        case GET_TRANSFER_HISTORY:
            out_msg.command = GET_TRANSFER_HISTORY;
            out_msg.timestamp = chrono::system_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            out_msg_string = serialize_message(out_msg);
            Crypto::aes_encrypt(session.aes_key, out_msg_string, out_buff);
            send_with_header(client_socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(client_socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }
            in_msg = deserialize_message(in_msg_string);

            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)))
            {
                cout << "[-] Received message with wrong HMAC" << endl;
            }

            if (in_msg.command != SUCCESS)
            {
                in_msg.content.clear();
                cout << "[-] Failed to get balance" << endl;
            }
            else
            {
                // separete transfers
                stringstream ss(in_msg.content);

                // Print all transfers untill variable ss is empty
                while (getline(ss, in_msg.content, '|'))
                {
                    transfer = deserialize_transfer(in_msg.content);
                    cout << transfer << endl;
                }
            }
            break;
        case CLOSE:
            out_msg.command = CLOSE;
            out_msg.timestamp = chrono::system_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-] Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);
            out_msg_string = serialize_message(out_msg);
            Crypto::aes_encrypt(session.aes_key, out_msg_string, out_buff);
            send_with_header(client_socket, out_buff, session.session_id);

            recv_with_header(client_socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }
            in_msg = deserialize_message(in_msg_string);
            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)))
            {
                cout << "[-] Received message with wrong HMAC" << endl;
            }

            if (in_msg.command != SUCCESS)
            {
                cout << "[-] Failed to close connection." << endl;
            }
            else
            {
                cout << "[+] Connection closed, destroying keys..." << endl;
                Client::destroy_session_keys();
                close(client_socket);
                cout << "[+] Done! Exiting..." << endl;
                exit(1);
            }
            break;

        default:
            cout << "Invalid option selected." << endl;
        }
    }
}

void Client::get_session()
{
    vector<unsigned char> in_buff;
    // vector<unsigned char> out_buff;

    string out_msg_string;
    Message out_msg;

    string in_msg_string;
    Message in_msg;
    Header in_msg_header;

    // Send client hello
    out_msg.command = CLIENT_HELLO;
    out_msg.content = bytes_to_hex(Crypto::generate_nonce(NONCE_LENGTH));
    out_msg_string = serialize_message(out_msg);
    vector<unsigned char> out_buff(out_msg_string.begin(), out_msg_string.end());

    send_with_header(client_socket, out_buff, 0);
    // receiv server hello
    recv_with_header(client_socket, in_buff, in_msg_header);
    in_msg_string = string(in_buff.begin(), in_buff.end());
    in_msg = deserialize_message(in_msg_string);

    // Extract ephemeral public key, signature and certificate
    stringstream ss(in_msg.content);
    string temp_str;
    getline(ss, temp_str, '-');
    vector<unsigned char> eph_pub_key = hex_to_bytes(temp_str);
    getline(ss, temp_str, '-');
    vector<unsigned char> signature = hex_to_bytes(temp_str); // <R || TpubK>
    getline(ss, temp_str, '-');
    vector<unsigned char> cert_vector = hex_to_bytes(temp_str);

    // Deserialize the certificate and extract the public key
    X509 *cert = deserialize_certificate(cert_vector);
    vector<unsigned char> server_pub_key = Crypto::read_public_key_from_cert(cert);

    if (!Crypto::verify_signature(out_msg.content + bytes_to_hex(eph_pub_key), signature, server_pub_key) || !Crypto::verify_certificate(cert_store, cert) || Crypto::read_owner_from_cert(cert) != EXPECTED_CERT_OWNER)
    {
        exit_with_error("[-] Error");
    }

    // Generate HMAC key and AES key
    session.hmac_key = Crypto::generate_nonce(HMAC_LENGTH);
    session.aes_key = Crypto::generate_nonce(AES_LENGTH);

    out_msg.command = KEY_EXCHANGE;
    out_msg.content = bytes_to_hex(session.aes_key) + '-' + bytes_to_hex(session.hmac_key);
    out_msg_string = serialize_message(out_msg);
    if (Crypto::rsa_encrypt(eph_pub_key, out_msg_string, out_buff) == -1)
    {
        exit_with_error("[-]Error failed to encrypt key exchange message");
    }
    // Key exchange
    send_with_header(client_socket, out_buff, 0);

    // Clear memory
    in_msg.content.clear();
    memset(eph_pub_key.data(), 0, eph_pub_key.size());

    // receiv server OK
    recv_with_header(client_socket, in_buff, in_msg_header);
    if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
    {
        cout << "[-] Key exchange failed: Can't decrypt session id" << endl;
    }
    in_msg = deserialize_message(in_msg_string);
    if (in_msg.command != SERVER_OK)
    {
        in_msg.content.clear();
        cout << "[-] Key exchange failed: wrong command" << endl;
    }

    session.session_id = static_cast<uint32_t>(stoul(in_msg.content));
}

void Client::display_options(bool logged_in)
{
    cout << "Choose one of the options:" << endl;
    if (!logged_in)
    {
        cout << "1. Log in" << endl;
    }
    cout << "2. Make transfer" << endl;
    cout << "3. Check balance" << endl;
    cout << "4. Show history of transfers" << endl;
    cout << "5. Safely close the connection to the server" << endl;
}
