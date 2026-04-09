// src/security/kms_server.cpp
// g++ src/security/kms_server.cpp -o kms_server -I./src/server/include -lssl -lcrypto -lpthread
#define CROW_ENABLE_SSL
#include "../server/include/crow_all.h"
#include <string>
// This is the Master Key that will be used for AES-256-GCM encryption at rest.
// In a production system, this would be injected via environment variables.
const std::string MASTER_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256

int main() {
    crow::SimpleApp app;

    // --- Secure Key Retrieval Endpoint ---
    CROW_ROUTE(app, "/internal/get_key").methods(crow::HTTPMethod::GET)([](const crow::request& req) {
        // Basic security check: ensure it's not being accessed from the public gateway
        std::string real_ip = req.get_header_value("X-Real-IP");
        if (!real_ip.empty()) {
            return crow::response(403, "Access Denied: Internal network only.");
        }

        crow::json::wvalue res;
        res["master_key"] = MASTER_KEY;
        return crow::response(200, res);
    });

    std::cout << "[*] Starting Internal KMS Server on port 8082 with HTTPS...\n";
    
    // Bind to 0.0.0.0 so Machine 1 and Machine 2 can reach it over the LAN
    // Enable SSL using the certificates we just generated
    app.port(8082).bindaddr("0.0.0.0")
       .ssl_file("certs/internal_node.crt", "certs/internal_node.key")
       .multithreaded().run();

    return 0;
}