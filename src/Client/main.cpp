#include "../../include/SecureBankApplication/Client.h"
#include "../../include/SecureBankApplication/Transaction.h"
#include "../../include/SecureBankApplication/Constants.h"
#include "../Utils.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <iostream> 
#include <vector>
#include <string>

using namespace std;

int main()
{
    cout << "Welcome to NM Bank!" << endl;
    Client client = Client();
    client.connect_with_server();
    client.destroy_session_keys();
    return 0;
}