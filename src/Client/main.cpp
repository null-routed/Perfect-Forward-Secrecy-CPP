#include "../../include/SecureBankApplication/Client.h"
#include "../../include/SecureBankApplication/Transaction.h"
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
    bool loged_in = false;
    std::cout << "Welcome to NM Bank!";
    while(true)
    {
        int option;
        Client::display_options();
        std::cout << "Enter the option number: ";
        std::cin >> option;
        
        switch (option)
        {
            case CLIENT_HELLO:
                // what do we need to create account?
                // username and password?

                if (loged_in)
                {
                    std::cout << "Invalid option selected." << std::endl;
                    break;
                }
                loged_in = true;
                break;

            case LOGIN:
                if (loged_in)
                {
                    std::cout << "Invalid option selected." << std::endl;
                    break;
                }
                // get username and password

                loged_in = true;
                break;

            case TRANSFER:

                break;
            
            case GET_BALANCE:
                int length_of_nonce = 16;//??
                std::vector<unsigned char> key;
                std::vector<unsigned char> content;
                std::vector<unsigned char> hmac;

                // Crypto::generateNonce(length_of_nonce);

                // Crypto::generateHMAC(key, content, hmac);

                Message message = Client::create_message(GET_BALANCE);
                Header header = Client::create_header(message, sender);
                // send header
                // send message
                // receiv balance
                break;

            case GET_TRANSFER_HISTORY:

                break;

            default:
                std::cout << "Invalid option selected." << std::endl;
                break;
            }
    }

    return 0;
}