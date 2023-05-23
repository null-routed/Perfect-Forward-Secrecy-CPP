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

bool loged_in;

int main()
{   
    loged_in = false;
    std::cout << "Welcome to NM Bank!";
    while(true)
    {
        // handle_server_connection(loged_in);
    }

    return 0;
}