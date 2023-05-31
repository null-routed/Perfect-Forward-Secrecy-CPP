#include "Client.h"
#include "Transaction.h"
#include "Constants.h"
#include "Utils.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <iostream>
#include <vector>
#include <string>

using namespace std;
using namespace Constants;

Client::Client()
{
    cert_store = X509_STORE_new();
    try
    {
        ca_cert = read_certificate_from_pem() // missing directory
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
    X509_store_free(cert_store);
}

// Looks good even though valread is never used
void Client::connect_with_server()
{
    int status, valread;
    // Create socket
    socket = socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0)
    {
        exit_with_error("[-] Error: failed to create clients socket\n");
    }

    // Fill in server IP address
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));

    server_addres.sin_family = AF_INET;
    server_addres.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addres.sin_addr) <= 0)
    {
        exit_with_error("[-] Error: invalid address/ Address not supported \n")
    }

    if ((status = connect(socket, (struct sockaddr *)&server_address, sizeof(server_address))) < 0)
    {
        exit_with_error("[-] Error: Connection Failed \n");
    }
    // return socket
}

void Client::destroy_session_keys()
{
#pragma optimize("", off)
    memset(sess.aes_key.data(), 0, session.aes_key.size());
    memset(sess.hmac_key.data(), 0, session.hmac_key.size());
#pragma optimize("", on)
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

    // string session_id;
    Session session;
    Transfer transfer;
    loged_in = false;

    Client::get_session(socket);

    int option;
    Client::display_options(loged_in);
    cout << "Enter the option number: ";
    cin >> option;

    while (option != CLOSE)
    {
        switch (option)
        {
        case LOGIN:
            if (loged_in)
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
            out_msg.timestamp = chrono::steady_clock::now();
            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            Crypto::aes_encrypt(session.aes_key, serialize_message(out_msg), out_buff);
            send_with_header(socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Key exchange failed: Can't decrypt session id" << endl;
                exit_with_error("[-] Error: failed to decrypt session id")
            }
            in_msg = deserialize_message(in_msg_string);

            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), out_msg.hmac))
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
                loged_in = true;
            }
            break;

        case TRANSFER:
            transfer.amount = 0.0;
            cout << "Enter username of receiver: ";
            cin >> transfer.receiver;

            while (transfer.amount <= 0.0)
            {
                cout << "Specify amount:" << endl;
                cin >> transfer.amount;
            }

            out_msg.command = TRANSFER;
            out_msg.content = transfer.receiver + '-' + to_string(transfer.amount);
            out_msg.timestamp = chrono::steady_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            Crypto::aes_encrypt(session.aes_key, serialize_message(out_msg), out_buff);
            send_with_header(socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }

            in_msg = deserialize_message(in_msg_string);

            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), out_msg.hmac))
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
            out_msg.timestamp = chrono::steady_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            Crypto::aes_encrypt(session.aes_key, serialize_message(out_msg), out_buff);
            send_with_header(new_socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }
            in_msg = deserialize_message(in_msg_string);

            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), out_msg.hmac))
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
            out_msg.timestamp = chrono::steady_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-]Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            Crypto::aes_encrypt(session.aes_key, serialize_message(out_msg), out_buff);
            send_with_header(socket, out_buff, session.session_id);

            // Receiv server response
            recv_with_header(socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }
            in_msg = deserialize_message(in_msg_string);

            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), out_msg.hmac))
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

                while (getline(ss, transfer_str, '|');)
                {
                    transfer = deserialize_transfer(transfer_str);
                    cout << transfer << endl;
                }
            }
            break;
        case CLOSE:
            out_msg.command = CLOSE;
            out_msg.timestamp = chrono::stead_clock::now();

            if (!Crypto::generate_hmac(session.hmac_key, serialize_message_for_hmac(out_msg), out_buff))
            {
                exit_with_error("[-] Error: failed to generate HMAC");
            }
            out_msg.hmac = bytes_to_hex(out_buff);

            Crypto::aes_encrypt(session.aes_key, serialize_message(out_msg), out_buff);
            send_with_header(socket, out_buff, session.session_id);

            recv_with_header(socket, in_buff, in_msg_header);
            if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Can't decrypt server response" << endl;
            }
            in_msg = deserialize_message(in_msg_string);
            if (!Crypto::verify_hmac(session.hmac_key, serialize_message_for_hmac(in_msg), out_msg.hmac))
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
                close(socket);
                cout << "[+] Done! Exiting..." << endl;
                exit(1);
            }
            
        default:
            cout << "Invalid option selected." << endl;
        }
    }
}

void Client::get_session()
{
    vector<unsigned char> in_buff;
    vector<unsigned char> out_buff;

    string out_msg_string;
    Message out_msg;

    string in_msg_string;
    Message in_msg;
    Header in_msg_header;

    // Send client hello
    out_msg.command = CLIENT_HELLO;
    out_msg.content = Crypto::generate_nonce(NONCE_LENGTH);
    out_msg_string = serialize_message(out_msg);
    out_buff(out_msg_string.begin(), out_msg_string.end());
    send_with_header(socket, out_buff, 0);

    // receiv server hello
    recv_with_header(socket, in_buff, in_msg_header);
    in_msg_string = string(in_buff.begin(), in_buff.end());
    in_msg = deserialize_message(in_msg_string);

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
    if (!verify_signature(in_msg_string, signature, server_pub_key) || !verify_certificate(cert_store, cert) || read_owner_from_cert(cert) != EXPECTED_CERT_OWNER)
    {
        exit_with_error("[-] Error");
    }

    // Generate HMAC key and AES key
    session.hmac_key = generate_nonce(HMAC_LENGTH);
    session.aes_key = generate_nonce(AES_LENGTH);

    out_msg.command = KEY_EXCHANGE;
    out_msg.content = bytes_to_hex(session.hmac_key) + '-' + bytes_to_hex(session.aes_key);
    if (rsa_encrypt(eph_pub_key, serialize_message(out_msg), out_buff) == -1)
    {
        exit_with_error("[-]Error failed to encrypt key exchange message");
    }
    // Key exchange
    send_with_header(socket, out_buff, 0);
    
    in_msg.content.clear();
    memset(eph_pub_key.data(), 0, eph_pub_key.size());
    memset(eph_priv_key.data(), 0, eph_priv_key.size());

    // receiv server OK
    recv_with_header(socket, in_buff, in_msg_header);
    // decrypt with aes_key
    if (Crypto::aes_decrypt(session.aes_key, in_buff, in_msg_string) == -1)
    {
        cout << "[-] Key exchange failed: Can't decrypt session id" << endl;
        return
    }
    in_msg = deserialize_message(in_msg_string);
    if (in_msg.command != SERVER_OK)
    {
        in_msg.content.clear();
        cout << "[-] Key exchange failed: wrong command" << endl;
        return
    }

    session.session_id = in_msg.content;
}

// Looks good, but I would also add a 5th option "CLOSE"
void Client::display_options(bool loged_in)
{
    cout << "Choose one of the options:" << endl;
    if (loged_in)
    {
        cout << "1. Log in" << endl;
    }
    cout << "2. Make transfer" << endl;
    cout << "3. Check balance" << endl;
    cout << "4. Show history of transfers" << endl;
    cout << "5. Safely close the connection to the server" << endl;
}

// Looks good
// Transfer Client::get_transfer_details(string sender)
// {
//     Transfer transfer;
//     trnsfer.amount = 0.0;
//     transfer.sender = sender;
//     cout << "Specify recipient:" << endl;
//     cin >> transfer.receiver;

//     while (transfer.amount <= 0.0)
//     {
//         cout << "Specify amount:" << endl;
//         cin >> transfer.amount;
//     }

//     transfer.timestamp = time(0);

//     return transfer;
// }