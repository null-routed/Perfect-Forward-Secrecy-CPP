
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
        destroy_session_keys(it->second);
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
                cout << "[+] Session timed-out, erasing keys. SessionID: " << it->first << endl;
                destroy_session_keys(it->second);
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
    if (pthread_create(&check_thread, NULL, &check_expired_sessions_wrapper, this))
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
        handle_client_connection(new_socket);
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

bool Server::is_user_logged_in(Session *sess)
{
    if (sess->user == "")
    {
        cout << "[-] User is not logged in, aborting..." << endl;
        return false;
    }
    else
    {
        return true;
    }
}

void Server::handle_login(Message &out_msg, Message &in_msg, Session *sess)
{
    out_msg.content = "";
    User usr;
    size_t pos = in_msg.content.find('-');
    string username = in_msg.content.substr(0, pos);
    string password = in_msg.content.substr(pos + 1);

    if (!is_alpha_numeric(username)) // Checking that the username string is safe to concatenate to a dir path
    {
        out_msg.command = INVALID_CREDENTIALS;
        cout << "[-] Username is not alphanumeric" << endl;
        return;
    }

    try
    {
        usr = load_user_data(BASE_PATH + username + FILE_EXT, enc_key);
    }
    catch (const runtime_error &e)
    {
        cerr << e.what() << endl;
        out_msg.command = INVALID_CREDENTIALS;
        return;
    }
    if (Crypto::verify_hash(password, hex_to_bytes(usr.hashed_password)))
    {
        cout << "[+] Login successful" << endl;
        sess->user = username;
    }
    else
    {
        cout << "[-] Invalid credentials" << endl;
        out_msg.command = INVALID_CREDENTIALS;
    }
    memset(&password[0], 0, password.size());
    memset(&in_msg.content[0], 0, in_msg.content.size());
}

void Server::handle_transfer(Message &out_msg, Message &in_msg, Session *sess)
{
    if (!is_user_logged_in(sess))
    {
        out_msg.command = UNAUTHORIZED;
        return;
    }

    out_msg.content = "";
    size_t pos = in_msg.content.find('-');
    double amount = stod(in_msg.content.substr(0, pos));
    string receiver_str = in_msg.content.substr(pos + 1);

    if (sess->user == receiver_str || !is_alpha_numeric(receiver_str))
    {
        cout << "[-] Receiver username is invalid" << endl;
        out_msg.command = INVALID_PARAMS;
        return;
    }
    User usr = load_user_data(BASE_PATH + sess->user + FILE_EXT, enc_key);
    User receiver;
    try
    {
        receiver = load_user_data(BASE_PATH + receiver_str + FILE_EXT, enc_key);
    }
    catch (const runtime_error &e)
    {
        cerr << e.what() << endl;
        out_msg.command = INVALID_PARAMS;
        return;
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
        write_user_data(BASE_PATH + sess->user + FILE_EXT, usr, enc_key);
        write_user_data(BASE_PATH + receiver_str + FILE_EXT, receiver, enc_key);
        clear_transfer(t);
    }
}

void Server::handle_get_balance(Message &out_msg, Session *sess)
{
    if (!is_user_logged_in(sess))
    {
        out_msg.command = UNAUTHORIZED;
        return;
    }

    User usr = load_user_data(BASE_PATH + sess->user + FILE_EXT, enc_key);
    out_msg.content = to_string(usr.balance);
}

void Server::handle_get_transfer_history(Message &out_msg, Session *sess)
{
    if (!is_user_logged_in(sess))
    {
        out_msg.command = UNAUTHORIZED;
        return;
    }

    User usr = load_user_data(BASE_PATH + sess->user + FILE_EXT, enc_key);

    int n_transfers = min(MAX_TRANSFERS, static_cast<int>(usr.transfer_history.size()));
    for (int i = 0; i < n_transfers; i++)
    {
        out_msg.content += serialize_transfer(usr.transfer_history[usr.transfer_history.size() - i - 1]);
        if ((i + 1) < n_transfers)
            out_msg.content += "-";
    }
}

void Server::handle_handshake(int new_socket, vector<unsigned char> &in_buff)
{

    string out_msg_string, in_msg_string;
    Message out_msg;
    Message in_msg = deserialize_message(string(in_buff.begin(), in_buff.end()));
    Header in_msg_header;
    vector<unsigned char> out_buff;

    if (in_msg.command == CLIENT_HELLO)
    {
        vector<unsigned char> eph_priv_key;
        vector<unsigned char> eph_pub_key;
        uint32_t session_id = generate_session();
        Session *sess = &(sessions[session_id]);

        Crypto::generate_key_pair(eph_priv_key, eph_pub_key);

        out_msg_string = serialize_message(generate_server_hello(in_msg.content, session_id, eph_pub_key));
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
            cout << "[-] Key exchange failed: Can't decrypt session keys" << endl;
            return;
        }
        in_msg = deserialize_message(in_msg_string);
        if (in_msg.command != KEY_EXCHANGE)
        {
            cout << "[-] Key exchange failed: wrong command" << endl;
            return;
        }

        // saving the key in the session struct and cleaning the string to make sure no sensitive data is stored
        size_t pos = in_msg.content.find('-');
        sess->aes_key = hex_to_bytes(in_msg.content.substr(0, pos));
        sess->hmac_key = hex_to_bytes(in_msg.content.substr(pos + 1));
        memset(&in_msg.content[0], 0, in_msg.content.size());
        memset(eph_priv_key.data(), 0, eph_priv_key.size());

        out_msg = {SERVER_OK, chrono::system_clock::now(), to_string(session_id), ""};
        out_msg_string = serialize_message(out_msg);

        Crypto::aes_encrypt(sess->aes_key, out_msg_string, out_buff);
        send_with_header(new_socket, out_buff, session_id);
        cout << "[+] Handshake completed for session id: " << session_id << endl;
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
Session *Server::get_session_by_id(uint32_t session_id)
{
    unordered_map<uint32_t, Session>::iterator it = sessions.find(session_id);
    if (it == sessions.end())
    {
        return nullptr;
    }

    return &(it->second);
}

void Server::delete_session_by_id(uint32_t session_id)
{
    unordered_map<uint32_t, Session>::iterator it = sessions.find(session_id);
    sessions.erase(it);
}

bool Server::is_message_valid(Message &in_msg, Session *sess)
{
    long long diff = to_milliseconds(chrono::system_clock::now()) - to_milliseconds(in_msg.timestamp);

    if (!Crypto::verify_hmac(sess->hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)) ||
        abs(diff) > RECV_WINDOW ||
        (to_milliseconds(in_msg.timestamp) <= to_milliseconds(sess->last_ping)))
    {
        cout << "[-] Invalid HMAC or timestamp, aborting..." << endl;
        return false;
    }

    return true;
}

void Server::handle_client_connection(int new_socket)
{
    bool must_delete = false;
    vector<unsigned char> in_buff, out_buff;
    string out_msg_string, in_msg_string;
    Message in_msg, out_msg;
    Header in_msg_header;
    uint32_t session_id;
    Session *sess;

    if (recv_with_header(new_socket, in_buff, in_msg_header) == -1)
    {
        cout << "[-] Aborted" << endl;
        return;
    }

    if (in_msg_header.sender)
    {
        session_id = in_msg_header.sender;

        sess = get_session_by_id(session_id);
        if (!sess)
        {
            out_msg.command = INVALID_SESSION;
            out_msg_string = serialize_message(out_msg);
            out_buff.assign(out_msg_string.begin(), out_msg_string.end());
            send_with_header(new_socket, out_buff, 0);
            return;
        }

        Crypto::aes_decrypt(sess->aes_key, in_buff, in_msg_string);
        in_msg = deserialize_message(in_msg_string);

        // Checking integrity, authenticity and replay attacks
        if (!is_message_valid(in_msg, sess))
        {
            in_msg.command = -1; // invalidating the session
        }
        else
        {
            out_msg.timestamp = in_msg.timestamp;
            out_msg.command = SUCCESS;
            sess->last_ping = in_msg.timestamp;
        }

        cout << "[+] Received " << commands_list[in_msg.command] << endl;
        switch (in_msg.command)
        {
        case LOGIN:
            handle_login(out_msg, in_msg, sess);
            break;

        case TRANSFER:
            handle_transfer(out_msg, in_msg, sess);
            break;

        case GET_BALANCE:
            handle_get_balance(out_msg, sess);
            break;

        case GET_TRANSFER_HISTORY:
            handle_get_transfer_history(out_msg, sess);
            break;

        case CLOSE:
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
        if (in_msg.command == GET_TRANSFER_HISTORY)
        {
            memset(&out_msg.content[0], 0, out_msg.content.size());
        }
        send_with_header(new_socket, out_buff, session_id);

        if (must_delete)
        {
            destroy_session_keys(*sess);
            delete_session_by_id(session_id);
        }
    }
    else
    {
        handle_handshake(new_socket, in_buff);
    }
}