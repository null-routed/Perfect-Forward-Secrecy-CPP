#include "Server.h"
#include <iostream>
#include <csignal>

Server *s;

void handle_signal(int signal)
{
    delete s;
    exit(signal);
}

int main()
{
    signal(SIGINT, &handle_signal);
    s = new Server();
    s->start_server();
}