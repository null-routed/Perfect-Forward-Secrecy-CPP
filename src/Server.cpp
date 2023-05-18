#include "../include/SecureBankApplication/Server.h"
#include "../include/SecureBankApplication/Constants.h"
#include "../include/SecureBankApplication/Transaction.h"
#include "Utils.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <iostream>
#include <vector>

using namespace std;
using namespace Constants;

Server::Server()
{
    pthread_mutex_init(&sessions_mutex, NULL);
}

Server::~Server()
{
    close(server_socket);
    pthread_mutex_destroy(&sessions_mutex);
}

bool Server::destroy_session_keys(Session &sess)
{
#pragma optimize("", off)
    memset(&sess.aes_session_key[0], 0, session.aes_session_key.size()); // can memset fail? If yes, check for result
    memset(&sess.hmac_session_key[0], 0, session.hmac_session_key.size());
#pragma optimize("", on)
    return true;
}

void Server::check_expired_sessions()
{
    while (true)
    {
        sleep(15);

        // Locking the muted on the shared variable
        pthread_mutex_lock(&sessions_mutex);

        // Iterating through all sessions, if the time since last ping is greater than TIMEOUT_TIME
        // we delete session keys and erase the session from the sessions map
        for (unordered_map<string, Session>::iterator it = sessions.begin(); it != sessions.end())
        {
            chrono::duration<double> elapsed = chrono::steady_clock::now() - p->second.last_ping;
            if (elapsed.count() > TIMEOUT_TIME)
            {
                if (Server::destroy_session_keys(p->second))
                {
                    it = sessions.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            else
            {
                ++it;
            }
        }

        // releasing the lock
        pthread_mutex_unlock(&sessions_mutex);
    }
}

void Server::start_server()
{
    pthread_t checkThread;
    if (pthread_create(&checkThread, NULL, Server::check_expired_sessions, this))
    {
        exit_with_error("[-] Could not start thread");
    }

    server_socket = socket(PF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    if (listen(server_socket, 50) == 0)
        cout << "[+] Listening..." << endl;
    else
        exit_with_error("[-] Error on listen");

    struct sockaddr_storage server_storage;
    socklen_t addr_size;
    addr_size = sizeof(server_storage);

    while (true)
    {
        int new_socket = accept(server_socket, (struct sockaddr *)&server_storage, &addr_size);

        if (new_socket < 0)
        {
            cout << "[-] Error on accept" << endl;
            continue;
        }

        Server::handle_client_connection(new_socket);
        close(new_socket);
    }
}

Message Server::generate_server_hello(string clientNonce)
{
    vector<unsigned char> tmp_private_key;
    vector<unsigned char> tmp_public_key;
    Crypto::generate_key_pair(tmp_private_key, tmp_public_key);
    Message server_hello;
    Message.command = SERVER_HELLO;
    Message.nonce = "";
    Message.content = bytes_to_hex(tmp_public_key) + "-" + Crypto::generate_signature(clientNonce + bytes_to_hex(tmp_public_key)) + "-" + serializedCERTIFICATE
}

int Server::send_with_header(int socket, const vector<unsigned char> &byte_array)
{

    Header header;
    header.sender = 0;
    header.length = byte_array.size();
}

vector<unsigned char> Server::recv_with_header(int socket)
{
    vector<unsigned char> header_buffer(HEADER_SIZE);
    int ret = recv(socket, header_buffer.data(), HEADER_SIZE, 0);
    if (ret <= 0)
    {
        return -1;
    }

    Header header = deserialize_header(header_buffer.data());

    vector<unsigned char> data_buffer(header.length);
    vector<unsigned char> tmp_buffer(MAX_BUFFER_SIZE);
    int recv_data = 0;

    while (recv_data < header.length)
    {
        ret = recv(socket, tmp_buffer.data(), MAX_BUFFER_SIZE, 0);
        if (ret <= 0)
        {
            return -1;
        }
        recv_data += ret;
        // copy the temp buffer in the data buffer, then execute the recv again if necessary
        copy(tmp_buffer.begin(), tmp_buffer.begin() + ret, data_buffer.begin() + recv_data);
    }

    return data_buffer;
}

void Server::handle_client_connection(int new_socket)
{
    Message message;
    if (recv_with_header(new_socket, message) == -1)
    {
        return;
    }

    if (header.sender)
    {
        // if sender is not null, the sender is already in a session
    }
    else
    {
        string stringified_data(data_buffer.begin(), data_buffer.end());
        message = deserialize_message(stringified_data);
        if (message.command == CLIENT_HELLO)
        {
            int session_id = Server::generate_session();
            Server::send_with_header(new_socket, serialized_message);
        }
        else
        {
        }
    }
}
