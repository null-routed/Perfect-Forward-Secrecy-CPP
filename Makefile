CXX = g++  
CERT_PATH =$(CURDIR)/cert/
BASE_PATH =$(CURDIR)/data/
# Maks
# CXXFLAGS = -std=c++11 -Wall -Wextra -Wno-deprecated-declarations -fcompare-debug-second -Iinclude/SecureBankApplication -pthread -lcrypto -L/usr/local/lib64 -DCERT_PATH=\"$(CERT_PATH)\"
# Niccolo
CXXFLAGS = -std=c++11 -Wall -Wextra -Wno-deprecated-declarations -Iinclude/SecureBankApplication -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -DCERT_PATH=\"$(CERT_PATH)\" -DBASE_PATH=\"$(BASE_PATH)\"
TARGET_DIR = bin
TARGET1 = $(TARGET_DIR)/Server/main  
TARGET2 = $(TARGET_DIR)/Client/main
SRC_DIR = src
SERVER_MAIN = $(SRC_DIR)/Server/main.cpp
CLIENT_MAIN = $(SRC_DIR)/Client/main.cpp
CPP_FILES = $(wildcard $(SRC_DIR)/*.cpp)
SERVER_CPP_FILES = $(filter-out $(SRC_DIR)/Client.cpp,$(CPP_FILES))
CLIENT_CPP_FILES = $(filter-out $(SRC_DIR)/Server.cpp,$(CPP_FILES))

all: dir $(TARGET1) $(TARGET2)

dir:  
	@mkdir -p $(TARGET_DIR)/Server
	@mkdir -p $(TARGET_DIR)/Client

$(TARGET1): $(SERVER_CPP_FILES) $(SERVER_MAIN)
	$(CXX) $^ -o $@ $(CXXFLAGS)

$(TARGET2): $(CLIENT_CPP_FILES) $(CLIENT_MAIN)
	$(CXX) $^ -o $@ $(CXXFLAGS) 
