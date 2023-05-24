#include "../src/Crypto.cpp"
#include "../src/Utils.cpp"
#include <iostream>

using namespace std;

int main(){
    
    X509* cert = read_certificate_from_pem("../cert/server_cert.pem");
    cout << read_owner_from_cert(cert) << endl;
    return 0;
}