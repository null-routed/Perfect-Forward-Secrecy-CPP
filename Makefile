CXX = g++  
CXXFLAGS = -std=c++11 -Wall -Wextra -Wno-deprecated-declarations -Iinclude/SecureBankApplication -lssl -lcrypto
TARGET_DIR = bin
TARGET1 = $(TARGET_DIR)/Server/main  
TARGET2 = $(TARGET_DIR)/Client/main
SRC_DIR = src
SERVER_MAIN = $(SRC_DIR)/Server/main.cpp
CLIENT_MAIN = $(SRC_DIR)/Client/main.cpp
SERVER_CPP_FILES = $(wildcard $(SRC_DIR)/*.cpp)
SERVER_CPP_FILES = $(filter-out $(SRC_DIR)/Client.cpp,$(SERVER_CPP_FILES))
CLIENT_CPP_FILES = $(wildcard $(SRC_DIR)/*.cpp)
CLIENT_CPP_FILES = $(filter-out $(SRC_DIR)/Server.cpp,$(CLIENT_CPP_FILES))

all: dir $(TARGET1) $(TARGET2)

dir:  
	@mkdir -p $(TARGET_DIR)/Server
	@mkdir -p $(TARGET_DIR)/Client

$(TARGET1): $(CPP_FILES) $(SERVER_MAIN)
	$(CXX) $^ -o $@ $(CXXFLAGS)

$(TARGET2): $(CPP_FILES) $(CLIENT_MAIN)
	$(CXX) $^ -o $@ $(CXXFLAGS) 
