#include "Client.h"
#include <iostream>

using namespace std;

int main()
{
    cout << "Welcome to NM Bank!" << endl;
    Client client = Client();
    client.handle_server_connection();
    client.destroy_session_keys();
    return 0;
}