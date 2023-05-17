#pragma once
#include <openssl/evp.h>

namespace Constants {
    constexpr int TIMEOUT_TIME = 5 * 60;
    constexpr int SALT_SIZE = 16;
    constexpr int MAX_BUFFER_SIZE = 4096; // Maximum buffer size for recv
    constexpr int USER_ID_LENGTH = 16; // User ID length, not sure if necessary
    constexpr int SERVER_PORT = 8080; // The port the server will use to handle incoming connections
    constexpr int INIT_SESSION = 0; // Commands
    constexpr int LOGIN = 1; 
    constexpr int TRANSFER = 2; 
    constexpr int GET_BALANCE = 3;
    constexpr int GET_TRANSFER_HISTORY = 4; 
}