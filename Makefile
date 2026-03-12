# Variables
CXX = g++
CXXFLAGS = -I./src/server/include -I./src/server/include/jwt-cpp/include
LIBS = -lsqlite3 -lssl -lcrypto -lpthread -lcurl
SERVER_SRC = src/server/main.cpp
CLIENT_SRC = src/client/client.cpp
MONITOR_SRC = src/monitoring/monitor.cpp
NGINX_CONF = src/api/nginx.conf

# Default target
all: prepare server client monitor

# 1. Create necessary directories
prepare:
	mkdir -p logs
	@echo "[INIT] Log directory ready."

# 2. Compile the Crow Server
server: $(SERVER_SRC)
	$(CXX) $(SERVER_SRC) -o app_server $(CXXFLAGS) -lsqlite3 -lssl -lcrypto -lpthread
	@echo "[BUILD] app_server compiled."

# 3. Compile the C++ Client
client: $(CLIENT_SRC)
	$(CXX) $(CLIENT_SRC) -o client $(CXXFLAGS) -lcurl
	@echo "[BUILD] client compiled."

monitor: $(MONITOR_SRC)
	$(CXX) $(MONITOR_SRC) -o monitor $(CXXFLAGS) -lcurl
	@echo "[BUILD] monitor compiled."

# 4. Clean start: Wipe DB and logs
clean:
	rm -f app_server client monitor app_data.db logs/*.log
	@echo "[CLEAN] Binaries, database, and logs removed."

# 5. Launch the full stack
# Note: Use '&' to run the server in background so Nginx can start
run: all
	@echo "[RUN] Starting Crow Server on 8080..."
	./app_server > logs/server_internal.log 2>&1  &  
	@sleep 1
	@echo "[RUN] Starting Security Monitor..."
	./monitor & 
	@sleep 2
	@echo "[RUN] Starting Nginx Gateway on 8081..."
	sudo nginx -p $(shell pwd) -c $(NGINX_CONF) -g "daemon off;"

# 6. Stop all processes
stop:
	-pkill -f app_server
	-sudo nginx -s stop
	@echo "[STOP] Server and Nginx stopped."