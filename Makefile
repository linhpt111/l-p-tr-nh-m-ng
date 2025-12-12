CC = gcc
CFLAGS = -Wall -Wextra -Iutils -Isocket_client -Isocket_server -Igui -g `pkg-config --cflags gtk+-3.0`
LDFLAGS = -lssl -lcrypto -lsqlite3 `pkg-config --libs gtk+-3.0`

# Directory structure
BIN_DIR = bin
BUILD_DIR = build
CLIENT_BUILD_DIR = $(BUILD_DIR)/socket_client
SERVER_BUILD_DIR = $(BUILD_DIR)/socket_server
UTILS_BUILD_DIR = $(BUILD_DIR)/utils
CLIENT_FUNCTIONS_BUILD_DIR = $(CLIENT_BUILD_DIR)/client_functions
SERVER_FUNCTIONS_BUILD_DIR = $(SERVER_BUILD_DIR)/server_functions

# Source directories
CLIENT_SRC_DIR = socket_client
CLIENT_FUNCTIONS_SRC_DIR = $(CLIENT_SRC_DIR)/client_functions
SERVER_SRC_DIR = socket_server
SERVER_FUNCTIONS_SRC_DIR = $(SERVER_SRC_DIR)/server_functions
UTILS_SRC_DIR = utils
GUI_SRC_DIR = gui

# Target binaries
CLIENT_BIN = $(BIN_DIR)/client
SERVER_BIN = $(BIN_DIR)/server

# Source files
CLIENT_SRC = $(CLIENT_SRC_DIR)/main.c $(wildcard $(CLIENT_FUNCTIONS_SRC_DIR)/*.c)
SERVER_SRC = $(SERVER_SRC_DIR)/main.c $(wildcard $(SERVER_FUNCTIONS_SRC_DIR)/*.c)
UTILS_SRC = $(wildcard $(UTILS_SRC_DIR)/*.c)
GUI_SRC = $(GUI_SRC_DIR)/gui.c

# Object files
CLIENT_OBJS = $(patsubst $(CLIENT_SRC_DIR)/%, $(CLIENT_BUILD_DIR)/%, $(CLIENT_SRC:.c=.o))
SERVER_OBJS = $(patsubst $(SERVER_SRC_DIR)/%, $(SERVER_BUILD_DIR)/%, $(SERVER_SRC:.c=.o))
UTILS_OBJS = $(patsubst $(UTILS_SRC_DIR)/%, $(UTILS_BUILD_DIR)/%, $(UTILS_SRC:.c=.o))
GUI_OBJS = $(patsubst $(GUI_SRC_DIR)/%, $(BUILD_DIR)/%, $(GUI_SRC:.c=.o))

# Default target
all: $(CLIENT_BIN) $(SERVER_BIN)

# Client binary
$(CLIENT_BIN): $(CLIENT_OBJS) $(UTILS_OBJS) $(GUI_OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Server binary
$(SERVER_BIN): $(SERVER_OBJS) $(UTILS_OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile client object files
$(CLIENT_BUILD_DIR)/%.o: $(CLIENT_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLIENT_BUILD_DIR)/%.o: $(CLIENT_FUNCTIONS_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile server object files
$(SERVER_BUILD_DIR)/%.o: $(SERVER_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_BUILD_DIR)/%.o: $(SERVER_FUNCTIONS_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile utility object files
$(UTILS_BUILD_DIR)/%.o: $(UTILS_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile GUI object files
$(BUILD_DIR)/%.o: $(GUI_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean
