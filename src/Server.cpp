
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstdlib>

#include "Server.h"
#include "Constants.h"
#include "Transaction.h"
#include "Crypto.h"
#include "Utils.h"

using namespace std;
using namespace Constants;

Server::Server()
{
    pthread_mutex_init(&sessions_mutex, NULL);
    try
    {
        own_cert = read_certificate_from_pem(string(CERT_PATH) + "server_cert.pem");
        priv_key = read_private_key_from_pem(string(CERT_PATH) + "server_key.pem");
        enc_key = read_aes_key(string(CERT_PATH) + "aes.key");
    }
    catch (const runtime_error &e)
    {
        exit_with_error("Could not load certificate / private key");
    }
}

Server::~Server()
{
    cout << "[+] Safely shutting down server..." << endl;
    pthread_mutex_lock(&sessions_mutex);
    for (unordered_map<uint32_t, Session>::iterator it = sessions.begin(); it != sessions.end(); ++it)
    {
        Server::destroy_session_keys(it->second);
    }

    X509_free(own_cert);
    close(server_socket);
    pthread_mutex_destroy(&sessions_mutex);
}

void Server::destroy_session_keys(Session &session)
{
    memset(session.aes_key.data(), 0, session.aes_key.size());
    memset(session.hmac_key.data(), 0, session.hmac_key.size());
}

void *Server::check_expired_sessions_wrapper(void *arg)
{
    Server *server = static_cast<Server *>(arg);
    server->check_expired_sessions();
    return nullptr;
}

void Server::check_expired_sessions()
{
    while (true)
    {
        sleep(SLEEP_TIME);

        // Locking the mutex on the shared variable
        pthread_mutex_lock(&sessions_mutex);

        for (unordered_map<uint32_t, Session>::iterator it = sessions.begin(); it != sessions.end();)
        {
            chrono::duration<double> elapsed = chrono::system_clock::now() - it->second.last_ping;
            if (elapsed.count() > TIMEOUT_TIME)
            {
                Server::destroy_session_keys(it->second);
                it = sessions.erase(it);
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

    pthread_t check_thread;
    if (pthread_create(&check_thread, NULL, &Server::check_expired_sessions_wrapper, this))
    {
        exit_with_error("[-] Fatal error while starting thread");
    }

    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        exit_with_error("[-] Fatal error while allocating socket");
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (::bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        exit_with_error("[-] Fatal error when binding socket");
    }

    if (listen(server_socket, 50) == 0)
        cout << "[+] Listening..." << endl;
    else
        exit_with_error("[-] Fatal error on listen");

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
        else
        {
            cout << "[+] Received new connection " << endl;
        }
        pthread_mutex_lock(&sessions_mutex);
        Server::handle_client_connection(new_socket);
        pthread_mutex_unlock(&sessions_mutex);
        close(new_socket);
    }
}

Message Server::generate_server_hello(string client_nonce, uint32_t session_id, vector<unsigned char> &eph_pub_key)
{
    Session session = sessions.find(session_id)->second;
    Message server_hello;
    server_hello.command = SERVER_HELLO;
    vector<unsigned char> signature;
    Crypto::generate_signature(priv_key, client_nonce + bytes_to_hex(eph_pub_key), signature);
    server_hello.content = bytes_to_hex(eph_pub_key) + "-" + bytes_to_hex(signature) + "-" + bytes_to_hex(serialize_certificate(own_cert));
    return server_hello;
}

uint32_t Server::generate_session()
{
    uint32_t session_id;
    do
    {
        vector<unsigned char> session_bytes = Crypto::generate_nonce(4);
        memcpy(&session_id, session_bytes.data(), sizeof(uint32_t));
    } while (sessions.find(session_id) != sessions.end());

    Session session;
    session.last_ping = chrono::system_clock::now();
    sessions[session_id] = session;
    sessions[session_id].user = "";

    return session_id;
}

bool is_user_logged_in(Message &out_msg, Session *sess)
{
    if(sess->user == ""){
        cout << "[-] User is not logged in, aborting..." << endl;
        out_msg.command = UNAUTHORIZED;
        return false;
    } else {
        return true;
    }
}

void Server::handle_client_connection(int new_socket)
{
    bool must_delete = false;
    vector<unsigned char> in_buff;
    vector<unsigned char> out_buff;

    string out_msg_string;
    Message out_msg;

    string in_msg_string;
    Message in_msg;
    Header in_msg_header;

    uint32_t session_id;
    Session *sess;

    size_t pos;
    if (recv_with_header(new_socket, in_buff, in_msg_header) == -1)
    {
        cout << "[-] Aborted" << endl;
        return;
    }
    if (in_msg_header.sender)
    {
        session_id = in_msg_header.sender;
        unordered_map<uint32_t, Session>::iterator it = sessions.find(session_id);
        if (it == sessions.end())
        {
            out_msg.command = INVALID_SESSION;
            out_msg_string = serialize_message(out_msg);
            out_buff.assign(out_msg_string.begin(), out_msg_string.end());
            send_with_header(new_socket, out_buff, 0);
            return;
        }
        sess = &(it->second);
        Crypto::aes_decrypt(sess->aes_key, in_buff, in_msg_string);
        in_msg = deserialize_message(in_msg_string);

        // Checking integrity, authenticity and replay attacks
        chrono::duration<long long, milli> diff = chrono::duration_cast<chrono::duration<long long, milli>>(chrono::system_clock::now() - in_msg.timestamp);
        if (!Crypto::verify_hmac(sess->hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)) || abs(diff.count()) > RECV_WINDOW || in_msg.timestamp <= sess->last_ping)
        {
            // invalidating the session
            in_msg.command = -1;
        }

        out_msg.timestamp = in_msg.timestamp;
        out_msg.command = SUCCESS;
        sess->last_ping = in_msg.timestamp;

        User usr, receiver;
        string username, password, receiver_str;
        double amount;
        int n_transfers;
        switch (in_msg.command)
        {
        case LOGIN:

            out_msg.content = "";
            pos = in_msg.content.find('-');
            username = in_msg.content.substr(0, pos);
            password = in_msg.content.substr(pos + 1);
            try
            {
                usr = load_user_data(BASE_PATH + username, enc_key);
            }
            catch (const runtime_error &e)
            {
                cerr << e.what() << endl;
                out_msg.command = INVALID_CREDENTIALS;
                break;
            }

            if (Crypto::verify_hash(password, hex_to_bytes(usr.hashed_password)))
            {
                sess->user = username;
            }
            else
            {
                out_msg.command = INVALID_CREDENTIALS;
            }
            password.clear();
            break;

        case TRANSFER:
            if(!is_user_logged_in(out_msg, sess)) break;
            out_msg.content = "";
            pos = in_msg.content.find('-');
            amount = stod(in_msg.content.substr(0, pos));
            receiver_str = in_msg.content.substr(pos + 1);
            usr = load_user_data(BASE_PATH + sess->user, enc_key);
            try
            {
                receiver = load_user_data(BASE_PATH + receiver_str, enc_key);
            }
            catch (const runtime_error &e)
            {
                cerr << e.what() << endl;
                out_msg.command = INVALID_PARAMS;
                break;
            }

            if (amount <= 0 || usr.balance < amount)
            {
                out_msg.command = INVALID_AMOUNT;
            }
            else
            {
                Transfer t = {usr.username, receiver.username, amount, time(nullptr)};
                usr.transfer_history.push_back(t);
                receiver.transfer_history.push_back(t);
                usr.balance -= amount;
                receiver.balance += amount;
                write_user_data(BASE_PATH + sess->user, usr, enc_key);
                write_user_data(BASE_PATH + receiver_str, receiver, enc_key);
            }

            break;

        case GET_BALANCE:
            cout << "Received GET_BALANCE." << endl;
            if(!is_user_logged_in(out_msg, sess)) break;

            usr = load_user_data(BASE_PATH + sess->user, enc_key);
            out_msg.content = to_string(usr.balance);
            break;

        case GET_TRANSFER_HISTORY:
            if(!is_user_logged_in(out_msg, sess)) break;
            usr = load_user_data(BASE_PATH + sess->user, enc_key);

            n_transfers = min(MAX_TRANSFERS, static_cast<int>(usr.transfer_history.size()));
            for (int i = 0; i < n_transfers; i++)
            {
                out_msg.content += serialize_transfer(usr.transfer_history[usr.transfer_history.size() - i - 1]);
                if ((i + 1) < n_transfers)
                    out_msg.content += "-";
            }
            break;

        case CLOSE:
            cout << "Received CLOSE, erasing session keys." << endl;
            must_delete = true;
            break;

        default:
            out_msg.command = INVALID_PARAMS;
            break;
        }

        Crypto::generate_hmac(sess->hmac_key, serialize_message_for_hmac(out_msg), out_buff);
        out_msg.hmac = bytes_to_hex(out_buff);

        out_msg_string = serialize_message(out_msg);
        Crypto::aes_encrypt(sess->aes_key, out_msg_string, out_buff);
        send_with_header(new_socket, out_buff, session_id);

        if (must_delete)
        {
            Server::destroy_session_keys(*sess);
            sessions.erase(it);
        }
    }
    else
    {
        in_msg = deserialize_message(string(in_buff.begin(), in_buff.end()));
        if (in_msg.command == CLIENT_HELLO)
        {
            vector<unsigned char> eph_priv_key;
            vector<unsigned char> eph_pub_key;
            session_id = Server::generate_session();
            sess = &(sessions[session_id]);
            Crypto::generate_key_pair(eph_priv_key, eph_pub_key);
            out_msg_string = serialize_message(Server::generate_server_hello(in_msg.content, session_id, eph_pub_key));
            out_buff.assign(out_msg_string.begin(), out_msg_string.end());
            if (send_with_header(new_socket, out_buff, 0) == -1)
            {
                cout << "[-] Key exchange failed: socket error" << endl;
                return;
            }

            if (recv_with_header(new_socket, in_buff, in_msg_header) == -1)
            {
                cout << "[-] Key exchange failed: socket error" << endl;
                return;
            }

            if (Crypto::rsa_decrypt(eph_priv_key, in_buff, in_msg_string) == -1)
            {
                cout << "[-] Key exchange failed: Can't decrypt session keys.ì" << endl;
                return;
            }
            in_msg = deserialize_message(in_msg_string);
            if (in_msg.command != KEY_EXCHANGE)
            {
                in_msg.content.clear();
                cout << "[-] Key exchange failed: wrong command.ì" << endl;
                return;
            }
            // saving the key in the session struct and cleaning the string to make sure no sensitive data is stored
            pos = in_msg.content.find('-');
            sess->aes_key = hex_to_bytes(in_msg.content.substr(0, pos));
            sess->hmac_key = hex_to_bytes(in_msg.content.substr(pos + 1));
            in_msg.content.clear();
            memset(eph_pub_key.data(), 0, eph_pub_key.size());
            memset(eph_priv_key.data(), 0, eph_priv_key.size());

            out_msg = {SERVER_OK, chrono::system_clock::now(), to_string(session_id), ""};
            out_msg_string = serialize_message(out_msg);

            Crypto::aes_encrypt(sess->aes_key, out_msg_string, out_buff);
            send_with_header(new_socket, out_buff, session_id);
            cout << "[+] Handshake completed for session id:" << session_id << endl;
        }
        else
        {
            cout << "[-] Invalid CLIENT_HELLO message, aborting" << endl;
            out_msg.command = INVALID_PARAMS;
            out_msg_string = serialize_message(out_msg);
            out_buff.assign(out_msg_string.begin(), out_msg_string.end());
            send_with_header(new_socket, out_buff, 0);
        }
    }
}