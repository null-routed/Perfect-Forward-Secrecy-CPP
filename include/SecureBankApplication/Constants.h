#pragma once

namespace Constants {
    const int MAX_BUFFER_SIZE = 1024; // Maximum buffer size for recv
    const int USER_ID_LENGTH = 16; // User ID length, not sure if necessary
    const int SERVER_PORT = 8080; // The port the server will use to handle incoming connections
    const int INIT_SESSION = 0; // Commands
    const int LOGIN = 1; 
    const int TRANSFER = 2; 
    const int GET_BALANCE = 3;
    const int GET_TRANSFER_HISTORY = 4; 
}