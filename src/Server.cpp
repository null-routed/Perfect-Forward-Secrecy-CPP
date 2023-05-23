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
    X509 *own_cert = read_certificate_from_pem();
}

Server::~Server()
{
    close(server_socket);
    pthread_mutex_destroy(&sessions_mutex);
}

bool Server::destroy_session_keys(Session &sess)
{
#pragma optimize("", off)
    memset(sess.aes_key.data(), 0, session.aes_key.size()); // can memset fail? If yes, check for result
    memset(sess.hmac_key.data(), 0, session.hmac_key.size());
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
        pthread_mutex_lock(&sessions_mutex);
        Server::handle_client_connection(new_socket);
        pthread_mutex_unlock(&sessions_mutex);
        close(new_socket);
    }
}

Message Server::generate_server_hello(string clientNonce, string session_id)
{
    Session session = sessions.find(session_id);
    Message server_hello;
    Message.command = SERVER_HELLO;
    Message.nonce = "";
    Message.content = bytes_to_hex(session.eph_pub_key) + "-" + Crypto::generate_signature(clientNonce + bytes_to_hex(session.eph_pub_key)) + "-" + bytes_to_hex(serialize_certificate(own_cert));
}

int Server::send_with_header(int socket, const vector<unsigned char> &data_buffer, uint32_t sender)
{
    Header header;
    header.length = data.size();
    header.sender = sender;
    vector<unsigned char> header_buffer = serialize_header(header);

    int ret = send(socket, header_buffer.data(), header_buffer.size(), 0);
    if (ret <= 0)
    {
        return -1;
    }

    ret = send(socket, data.data(), data.size(), 0);
    if (ret <= 0)
    {
        return -1;
    }

    return ret;
}

int Server::recv_with_header(int socket, vector<unsigned char> &data_buffer, Header &header)
{
    vector<unsigned char> header_buffer(HEADER_SIZE);
    int ret = recv(socket, header_buffer.data(), HEADER_SIZE, 0);
    if (ret <= 0)
    {
        return -1;
    }

    header = deserialize_header(header_buffer.data());

    data_buffer.resize(header.length);
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
        copy(tmp_buffer.begin(), tmp_buffer.begin() + ret, data_buffer.begin() + recv_data - ret);
    }

    return recv_data;
}

string Server::generate_session()
{
    string session_id;
    do
    {
        session_id = byte_to_hex(Crypto::generate_nonce(8));
    } while (sessions.find(session_id) != sessions.end());

    Session session;
    Crypto::generate_key_pair(session.eph_priv_key, session.eph_pub_key);
    session.last_ping = chrono::steady_clock::now();
    sessions[session_id] = session;
    sessions[session_id].user = "";

    return session_id;
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

    string session_id;
    Session sess;

    if (recv_with_header(new_socket, in_buff, in_msg_header) == -1)
    {
        return;
    }

    if (header.sender)
    {
        session_id = to_string(header.sender);
        unordered_map<string, Session>::iterator it = sessions.find(session_id);
        if (it == sessions.end())
        {
            out_msg.command = INVALID_PARAMS;
            out_msg_string = serialize_message(out_msg);
            out_buff(out_msg_string.begin(), out_msg_string.end());
            Server::send_with_header(new_socket, out_buff, 0);
            return;
        }
        sess = it->second;
        sess.last_ping = chrono::steady_clock::now();
        Crypto::aes_decrypt(sess.aes_key, in_buff, in_msg_string);
        in_msg = deserialize_message(in_msg_string);

        // checking for a valid hmac and for replay attacks
        if (!Crypto::verify_hmac(sess.hmac_key, serialize_message_for_hmac(in_msg), hex_to_bytes(in_msg.hmac)) || find(sess.session_nonces.begin(), sess.session_nonces.end(), in_msg.nonce) != sess.session_nonces.end())
        {
            // invalidating the session
            msg.command = -1;
        }

        out_msg.nonce = in_msg.nonce;
        out_msg.command = SUCCESS;
        switch (in_msg.command)
        {
        case LOGIN:

            out_msg.content = "";
            size_t pos = msg.content.find('-');
            string username = in_msg.content.substr(0, pos);
            string password = in_msg.content.substr(pos + 1);

            User usr = load_user_data(BASE_PATH + username, enc_key);
            if (Crypto::veryify_hash(password, hex_to_bytes(usr.password)))
            {
                sess.user = username;
            }
            else
            {
                out_msg.command = INVALID_CREDENTIALS;
            }
            password.clear();
            break;

        case TRANSFER:
            if (sess.user == "")
            {
                out_msg.command = UNAUTHORIZED;
                break;
            }
            out_msg.content = "";
            size_t pos = msg.content.find('-');
            double amount = stod(in_msg.content.substr(0, pos));
            string receiver_str = in_msg.content.substr(pos + 1);
            User sender = load_user_data(BASE_PATH + sess.user, enc_key);
            User receiver = load_user_data(BASE_PATH + receiver_str, enc_key);

            if (amount <= 0 || sender.balance < amount)
            {
                out_msg.command = INVALID_AMOUNT;
            }
            else
            {
                sender.balance -= amount;
                receiver.balance += amount;
                write_user_data(BASE_PATH + sess.user, enc_key);
                write_user_data(BASE_PATH + receiver_str, enc_key)
            }

            break;
        case GET_BALANCE:
            if (sess.user == "")
            {
                out_msg.command = UNAUTHORIZED;
                break;
            }

            User usr = load_user_data(BASE_PATH + sess.user, enc_key);
            out_msg.content = to_string(usr.balance);

            break;
        case GET_TRANSFERS:
            if (sess.user == "")
            {
                out_msg.command = UNAUTHORIZED;
                break;
            }
            User usr = load_user_data(BASE_PATH + sess.user, enc_key);

            for(int i = 0; i < min(MAX_TRANSFERS, usr.transfer_history.size()); i++){
                out_msg.content += serialize_transfer(usr.transfer_history[usr.transfer_history.size() - i - 1]);
                if(i + 1 < min(MAX_TRANSFERS, usr.transfer_history.size())) out_msg.content += "|"
            }
            break;
        case CLOSE:
            must_delete = true;
            break;
        default:
            out_msg.command = INVALID_PARAMS;
            break;
        }

        Crypto::generateHMAC(sess.hmac_key, serialize_message_for_hmac(out_msg), out_buff);
        out_msg.hmac = bytes_to_hex(out_buff);

        Crypto::aes_encrypt(sess.aes_key, serialize_message(out_msg), out_buff);
        send_with_header(new_socket, out_buff, session_id);

        if(must_delete){
            Server::destroy_session_keys(sess);
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
            sess = sessions.find(session_id)->second;
            out_msg_string = serialize_message(Server::generate_server_hello(in_msg.content, session_id));
            out_buff(out_msg_string.begin(), out_msg_string.end());
            Server::send_with_header(new_socket, out_buff, 0);

            Server::recv_with_header(new_socket, in_buff, in_msg_header);
            Crypto::RSA_decrypt(eph_priv_key, in_buff, in_msg_string);
            in_msg = deserialize_message(in_msg_string);

            // saving the key in the session struct and cleaning the string to make sure no sensitive data is stored
            size_t pos = msg.content.find('-');
            sess.aes_key = hex_to_bytes(in_msg.content.substr(0, pos));
            sess.hmac_key = hex_to_bytes(in_msg.content.substr(pos + 1));

            in_msg.content.clear();
            memset(eph_pub_key.data(), 0, eph_pub_key.size());
            memset(eph_priv_key.data(), 0, eph_priv_key.size());

            out_msg = {SERVER_OK, "", session_id, ""};
            out_msg_string = serialize_message(out_msg);
            Crypto::aes_encrypt(sess.aes_key, out_msg_string, out_buff);
            Server::send_with_header(new_socket, out_buff, session_id);
        }
        else
        {
            out_msg.command = INVALID_PARAMS;
            out_msg_string = serialize_message(out_msg);
            out_buff(out_msg_string.begin(), out_msg_string.end());
            Server::send_with_header(new_socket, out_buff, 0);
        }
    }
}
