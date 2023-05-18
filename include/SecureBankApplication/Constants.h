#pragma once

namespace Constants {
    const int TIMEOUT_TIME = 5 * 60;

    const int HEADER_SIZE = 64;
    const int SALT_SIZE = 16;
    const int MAX_BUFFER_SIZE = 4096; // Maximum buffer size for recv

    const int USER_ID_LENGTH = 16; // User ID length, not sure if necessary
    const int SERVER_PORT = 8080; // The port the server will use to handle incoming connections

    const int CLIENT_HELLO = 0; // Commands
    const int SERVER_HELLO = 1;
    const int LOGIN = 1; 
    const int TRANSFER = 2; 
    const int GET_BALANCE = 3;
    const int GET_TRANSFER_HISTORY = 4; 
}