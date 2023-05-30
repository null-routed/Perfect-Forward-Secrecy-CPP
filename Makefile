CXX = g++  
CXXFLAGS = -std=c++11 -Wall -Wextra -Wno-deprecated-declarations -Iinclude/SecureBankApplication -L/usr/include/openssl -lcrypto  # Linking lcrypto
TARGET_DIR = bin # Bin files
TARGET1 = $(TARGET_DIR)/server  
TARGET2 = $(TARGET_DIR)/client 
OBJ_DIR = obj  
SRC_DIR = src  # Source files

SERVER_MAIN = $(SRC_DIR)/Server/main.cpp  # Source file for server main
CLIENT_MAIN = $(SRC_DIR)/Client/main.cpp  # Source file for client main
CPP_FILES = $(wildcard $(SRC_DIR)/*.cpp)  # Wildcard to find all cpp files
OBJ_FILES = $(addprefix $(OBJ_DIR)/, $(notdir $(CPP_FILES:.cpp=.o)))  

# Default Rule
all: dir $(TARGET1) $(TARGET2)  

dir:  
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(TARGET_DIR)

$(TARGET1): $(OBJ_FILES) $(OBJ_DIR)/main_server.o 
	$(CXX) $^ -o $@ $(CXXFLAGS)  

$(TARGET2): $(OBJ_FILES) $(OBJ_DIR)/main_client.o 
	$(CXX) $^ -o $@ $(CXXFLAGS) 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp  
	$(CXX) -c $< -o $@ $(CXXFLAGS)  

$(OBJ_DIR)/main_server.o: $(SERVER_MAIN) 
	$(CXX) -c $< -o $@ $(CXXFLAGS)  

$(OBJ_DIR)/main_client.o: $(CLIENT_MAIN)
	$(CXX) -c $< -o $@ $(CXXFLAGS) 

.PHONY: clean 

clean:  # Rule for cleaning up the project
	rm -f $(OBJ_DIR)/*.o $(TARGET1) $(TARGET2)  
