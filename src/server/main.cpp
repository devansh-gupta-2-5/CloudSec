// server/main.cpp
// g++ main.cpp -o app_server -I./include -I./include/jwt-cpp/include -lsqlite3 -lssl -lcrypto -lpthread
#include "include/crow_all.h"
#include <sqlite3.h>
#include <jwt-cpp/jwt.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <unordered_set>
#include <mutex>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cctype>
// --- Global State ---
std::unordered_set<std::string> blocked_ips;
std::mutex blocklist_mutex;
std::mutex log_mutex;
sqlite3 *db; // Global DB connection
const std::string SECRET_KEY = "super_secret_assignment_key";

// --- Utility: Secure Salt Generation ---
// Generates a cryptographically secure random salt and returns it as a hex string
std::string generate_salt(size_t length = 16)
{
    unsigned char buffer[length];
    if (RAND_bytes(buffer, length) != 1)
    {
        throw std::runtime_error("Failed to generate secure random bytes for salt.");
    }
    std::stringstream ss;
    for (size_t i = 0; i < length; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }
    return ss.str();
}

// --- Utility: SHA-256 Password Hashing with salt ---
std::string hash_password(const std::string &password, const std::string &salt)
{
    std::string salted_password = salt + password; // Prepend salt to password
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(salted_password.c_str()), salted_password.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// --- Utility: Strong Password Validation ---
bool is_strong_password(const std::string& password) {
    if (password.length() < 8 || password.length() > 20) {
        return false;
    }
    
    bool has_lower = false;
    bool has_upper = false;
    bool has_digit = false;
    bool has_special = false;
    
    for (char c : password) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else if (std::ispunct(c) || !std::isalnum(c)) has_special = true;
    }
    
    return has_lower && has_upper && has_digit && has_special;
}

// --- Utility: Audit Logging ---
// [DEPRECATED] Writes to the CloudSec/logs/auth.log file
void log_auth_event(const std::string &ip, const std::string &event, bool success)
{
    // Navigating up two directories to hit the required Assignment3/logs/ folder
    std::lock_guard<std::mutex> lock(log_mutex); // Ensure thread-safe logging
    std::ofstream log_file("logs/auth.log", std::ios_base::app);
    if (log_file.is_open())
    {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::string time_str = std::ctime(&now);
        time_str.pop_back(); // Remove newline from ctime

        log_file << "[" << time_str << "] IP: " << ip
                 << " | Status: " << (success ? "SUCCESS" : "FAILED")
                 << " | Event: " << event << "\n";
    }
    else
    {
        std::cerr << "[WARNING] Could not open auth.log. Make sure the logs/ directory exists.\n";
    }
}

// --- Utility: Master Event Logger ---
// Writes to specific files in the CloudSec/logs/ directory
void log_event(const std::string &filename, const std::string &ip, const std::string &event, const std::string &status)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream log_file("logs/" + filename, std::ios_base::app);
    if (log_file.is_open())
    {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::string time_str = std::ctime(&now);
        time_str.pop_back();

        log_file << "[" << time_str << "] IP: " << ip
                 << " | Status: " << status
                 << " | Event: " << event << "\n";
    }
    else
    {
        std::cerr << "[WARNING] Could not open " << filename << ". Check directories.\n";
    }
}

// --- Database Initialization ---
void init_database()
{
    int rc = sqlite3_open("app_data.db", &db);
    if (rc)
    {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n";
        exit(1);
    }

    const char *sql_create = "CREATE TABLE IF NOT EXISTS users ("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                             "username TEXT UNIQUE NOT NULL,"
                             "password_hash TEXT NOT NULL,"
                             "salt TEXT NOT NULL,"
                             "role TEXT NOT NULL);";

    char *errMsg = nullptr;
    sqlite3_exec(db, sql_create, 0, 0, &errMsg);

    // Insert default admin safely with a HASHED password
    std::string salt = generate_salt();
    std::string admin_pass_hashed = hash_password("admin123", salt);
    std::string mod_pass_hashed = hash_password("mod123", salt);
    std::string user_pass_hashed = hash_password("user123", salt);
    std::string sql_insert_admin = "INSERT INTO users (username, password_hash, salt, role) VALUES ('admin', '" + admin_pass_hashed + "', '" + salt + "', 'admin');";
    log_event("auth.log", "127.0.0.1", "Default admin user created", "INFO");
    sqlite3_exec(db, sql_insert_admin.c_str(), 0, 0, &errMsg);

    if (errMsg)
        sqlite3_free(errMsg);
    std::cout << "Database initialized successfully with hashed credentials.\n";
}

// --- Security Middleware ---
struct SecurityMiddleware
{
    struct context
    {
    };
    void before_handle(crow::request &req, crow::response &res, context &ctx)
    {
        std::string client_ip = req.get_header_value("X-Real-IP");
        if (client_ip.empty())
            client_ip = req.remote_ip_address;

        std::lock_guard<std::mutex> lock(blocklist_mutex);
        if (blocked_ips.find(client_ip) != blocked_ips.end())
        {
            res.code = 403;
            res.body = "Access Denied: IP Banned due to suspicious activity.";
            // Log this to threats, as a banned IP is still trying to access the server
            log_event("threats.log", client_ip, "Blocked Request (Banned IP)", "DENIED");
            res.end();
        }
    }
    void after_handle(crow::request &req, crow::response &res, context &ctx) {}
};

int main()
{
    init_database();
    crow::App<SecurityMiddleware> app;

    // --- Route 1: The Hidden Ban Endpoint ---
    CROW_ROUTE(app, "/internal/ban").methods(crow::HTTPMethod::POST)([](const crow::request &req)
                                                                     {
        // If X-Real-IP is set, it means an external user tried to access this via Nginx. Block it.
        std::string real_ip = req.get_header_value("X-Real-IP");
        if (!real_ip.empty() || req.remote_ip_address != "127.0.0.1") {
            log_event("threats.log", real_ip, "Unauthorized internal access attempt", "THREAT");
            return crow::response(401, "Unauthorized: Internal API only.");
        }
        auto json_body = crow::json::load(req.body);
        if (!json_body || !json_body.has("ip")) return crow::response(400, "Invalid JSON");

        std::string bad_ip = json_body["ip"].s();
        std::lock_guard<std::mutex> lock(blocklist_mutex);
        blocked_ips.insert(bad_ip);
        log_event("mitigation.log", "127.0.0.1", "Automated ban applied to IP: " + bad_ip, "ACTION_TAKEN");
        return crow::response(200, "IP Banned successfully."); });

    // --- Route 2: Secure Database Login ---
    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([](const crow::request &req)
                                                              {

        std::string client_ip = req.get_header_value("X-Real-IP");
        if (client_ip.empty()) client_ip = req.remote_ip_address;

        auto json = crow::json::load(req.body);
        if (!json || !json.has("username") || !json.has("password")) {
            return crow::response(400, "Missing credentials");
        }

        std::string user = json["username"].s();
        std::string pass = json["password"].s();

        // PREPARED STATEMENT to prevent SQL Injection
        const char* sql = "SELECT password_hash, salt, role FROM users WHERE username = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string db_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                std::string db_salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                std::string db_role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                
                std::string hashed_pass_attempt = hash_password(pass, db_salt);

                if (db_hash == hashed_pass_attempt) {
                    // Password matches hash!
                    auto token = jwt::create()
                        .set_issuer("cloud_auth_server")
                        .set_type("JWS")
                        .set_payload_claim("user", jwt::claim(user))
                        .set_payload_claim("role", jwt::claim(db_role))
                        .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes(15))
                        .sign(jwt::algorithm::hs256{SECRET_KEY});

                    log_event("auth.log", client_ip, "Login successful for user: " + user, "SUCCESS");
                    sqlite3_finalize(stmt);
                    crow::json::wvalue response_json;
                    response_json["token"] = token;
                    return crow::response(200, response_json);
                }
            }
            sqlite3_finalize(stmt);
        }

        // If we reach here, either the user doesn't exist or password didn't match
        log_event("auth.log", client_ip, "Failed login attempt for user: " + user, "FAILED");
        return crow::response(401, "Invalid credentials"); });

        // --- Route 3A: Public User Registration ---
    CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([](const crow::request &req)
    {
        std::string client_ip = req.get_header_value("X-Real-IP");
        if (client_ip.empty()) client_ip = req.remote_ip_address;

        auto json = crow::json::load(req.body);
        if (!json || !json.has("username") || !json.has("password")) {
            return crow::response(400, "Missing fields (username, password)");
        }

        std::string new_user = json["username"].s();
        std::string new_pass = json["password"].s();

        // Enforce strong password constraints
        if (!is_strong_password(new_pass)) {
            log_event("auth.log", client_ip, "Failed registration: Weak password for user " + new_user, "FAILED");
            return crow::response(400, "Password must be 8-20 characters long, and include at least one uppercase letter, one lowercase letter, one number, and one special character.");
        }

        std::string new_salt = generate_salt();
        std::string new_hash = hash_password(new_pass, new_salt);
        std::string default_role = "user";

        // Insert new user into the database
        const char* sql = "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, new_user.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, new_hash.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, new_salt.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, default_role.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                sqlite3_finalize(stmt);
                log_event("auth.log", client_ip, "New user registered successfully: " + new_user, "SUCCESS");
                return crow::response(201, "Registration successful. Please proceed to /login");
            }
        }
        
        sqlite3_finalize(stmt);
        log_event("auth.log", client_ip, "Failed registration: Username already exists (" + new_user + ")", "FAILED");
        return crow::response(409, "Username already exists");
    });

    // --- Route 3: Protected Resource with JWT Tamper Auditing ---
    CROW_ROUTE(app, "/api/data")
    ([](const crow::request &req)
     {
        std::string client_ip = req.get_header_value("X-Real-IP");
        if (client_ip.empty()) client_ip = req.remote_ip_address;

        auto auth_header = req.get_header_value("Authorization");
        if (auth_header.empty() || auth_header.substr(0, 7) != "Bearer ") {
            return crow::response(401, "Missing or invalid token");
        }

        std::string token = auth_header.substr(7);
        try {
            auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{SECRET_KEY})
                .with_issuer("cloud_auth_server");
            verifier.verify(decoded);

            std::string role = decoded.get_payload_claim("role").as_string();

        if (role == "admin") {
            return crow::response(200, "ADMIN PANEL: Access to all system logs and user management.");
        } else if (role == "moderator") {
            return crow::response(200, "MODERATOR PANEL: Access to user reports and content moderation.");
        } else {
            return crow::response(200, "USER PANEL: Welcome to your dashboard.");
        }
        } catch (const std::exception& e) {
            // CRITICAL AUDIT: Someone sent a token with a forged signature or altered payload!
            log_event("threats.log", client_ip, "JWT Tampering / Invalid Token Signature", "THREAT_DETECTED");
            return crow::response(401, "Token verification failed");
        } });

    CROW_ROUTE(app, "/whoami")
    ([](const crow::request &req)
     {
    // Get the IP from Nginx's header
    std::string client_ip = req.get_header_value("X-Real-IP");
    
    // If empty, it means we bypassed Nginx and hit the server directly
    if (client_ip.empty()) client_ip = req.remote_ip_address;

    crow::json::wvalue res;
    res["your_ip"] = client_ip;
    res["source"] = req.get_header_value("X-Real-IP").empty() ? "Direct to Server" : "Via Nginx Gateway";
    return res; });

    CROW_ROUTE(app, "/admin/add_user").methods(crow::HTTPMethod::POST)([&](const crow::request &req)
                                                                       {
    // 1. JWT Authentication Check
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.empty() || auth_header.substr(0, 7) != "Bearer ") {
        log_event("threats.log", req.remote_ip_address, "Unauthorized attempt to access admin endpoint", "THREAT");
        return crow::response(401, "Admin access required");
    }

    try {
        std::string token = auth_header.substr(7);
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{SECRET_KEY}).with_issuer("cloud_auth_server");
        verifier.verify(decoded);

        if (decoded.get_payload_claim("role").as_string() != "admin") {
            log_event("threats.log", req.remote_ip_address, "Unauthorized attempt to access admin endpoint", "THREAT");
            return crow::response(403, "Forbidden: Only admins can add users");
        }

        // 2. Parse New User Data
        auto json = crow::json::load(req.body);
        if (!json || !json.has("username") || !json.has("password") || !json.has("role")) {
            log_event("threats.log", req.remote_ip_address, "Invalid user data provided", "THREAT");
            return crow::response(400, "Missing fields (username, password, role)");
        }

        std::string new_user = json["username"].s();
        std::string new_pass = json["password"].s();
        std::string new_role = json["role"].s();

        // Enforce strong password constraints for admins too
        if (!is_strong_password(new_pass)) {
            log_event("threats.log", req.remote_ip_address, "Admin attempted to create user with weak password: " + new_user, "REJECTED");
            return crow::response(400, "Password must be 8-20 characters, with 1 uppercase, 1 lowercase, 1 number, and 1 special char.");
        }

        // 3. Hash and Store
        std::string new_salt = generate_salt();
        std::string new_hash = hash_password(new_pass, new_salt);

        const char* sql = "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, new_user.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, new_hash.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, new_salt.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, new_role.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                sqlite3_finalize(stmt);
                log_event("auth.log", decoded.get_payload_claim("user").as_string(), "Admin added new user: " + new_user, "SUCCESS");
                return crow::response(201, "User created successfully");
            }
        }
        sqlite3_finalize(stmt);
        return crow::response(500, "Database error or user already exists");

    } catch (...) {
        log_event("threats.log", req.remote_ip_address, "Invalid token provided", "THREAT");
        return crow::response(401, "Invalid token");
    } });

    app.port(8080).multithreaded().run();
    sqlite3_close(db); // Cleanup on exit
    return 0;
}
