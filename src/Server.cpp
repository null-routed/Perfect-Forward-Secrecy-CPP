#include "../include/SecureBankApplication/Server.h"
#include "../include/SecureBankApplication/Constants.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <iostream> 

using namespace std;

Server::Server()
{
    pthread_mutex_init(&sessions_mutex, NULL);
}

Server::~Server()
{
    pthread_mutex_destroy(&sessions_mutex);
}

bool Server::destroy_session_keys(Session &sess)
{
    memset(&sess.aes_session_key[0], 0, session.aes_session_key.size()); // can memset fail? If yes, check for result
    memset(&sess.hmac_session_key[0], 0, session.hmac_session_key.size());
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
            chrono::duration<double> elapsed = p->second.last_ping - chrono::steady_clock::now();
            if (elapsed.count() > Constants::TIMEOUT_TIME)
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
    if(!pthread_create(&checkThread, NULL, Server::check_expired_sessions, this))
    {
        exit_with_error("[-] Could not start thread");
    }

    int server_socket = socket(PF_INET, SOCK_STREAM, 0);

    // Define the server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(Constants::SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_addr));

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