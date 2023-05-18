#ifndef CLIENT_H
#define CLIENT_H

#include <vector>

class Client
{
public:

    void Client();

    void ~Client();

    // void start_client();

    void connect_with_server();

    void disconnect_with_server();

    void create_message();

    void send_message();

    void receiv_message();
};