// Utils.h

#include <vector>
#include <string>
#include <Transaction.h>

std::vector<unsigned char> serializeMessage(const Message &toSerialize);

Message deserializeMessage(const std::vector<unsigned char> &serialized);

void exitWithError(const std::string &error);