/* g++ node_server.cpp -o node_server \
    -I$(brew --prefix mariadb-connector-c)/include/mariadb \
    -I$(brew --prefix openssl)/include \
    -I$(brew --prefix asio)/include \
    -L$(brew --prefix mariadb-connector-c)/lib \
    -L$(brew --prefix openssl)/lib \
    -lmariadb -lssl -lcrypto -lcurl
*/
// g++ node_server.cpp -o node_server -I/usr/include/mariadb -lmariadb -lssl -lcrypto -lcurl -lpthread
#define CROW_ENABLE_SSL
#include "include/crow_all.h" 
#include <mysql.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <thread> // NEW: For background replication

// --- Configuration ---
const std::string MACHINE_0_IP = "192.168.X.X"; // CHANGE THIS: Hub IP
const std::string PEER_IP = "192.168.Y.Y";      // CHANGE THIS: The OTHER Node's IP
const std::string NODE_NAME = "node_mac";       // CHANGE THIS: "node_mac" or "node_ubuntu"

std::string ACTIVE_MASTER_KEY = "";
MYSQL *db_conn;

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// --- 1. Startup Infrastructure ---
bool fetch_master_key() {
    std::cout << "[*] Fetching Master Key from KMS...\n";
    CURL *curl = curl_easy_init();
    if (!curl) return false;

    std::string url = "https://" + MACHINE_0_IP + ":8082/internal/get_key";
    std::string resp;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CAINFO, "certs/rootCA.crt");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        auto json = crow::json::load(resp);
        if (json && json.has("master_key")) {
            ACTIVE_MASTER_KEY = json["master_key"].s();
            std::cout << "[+] Master Key acquired.\n";
            return true;
        }
    }
    return false;
}

bool init_db() {
    db_conn = mysql_init(NULL);
    mysql_ssl_set(db_conn, NULL, NULL, "certs/rootCA.crt", NULL, NULL);
    my_bool my_false = 0;
    mysql_options(db_conn, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &my_false);

    if (mysql_real_connect(db_conn, MACHINE_0_IP.c_str(), "cloudnode", "securepass123", "cloudsec_db", 3306, NULL, CLIENT_SSL) == NULL) {
        return false;
    }
    std::cout << "[+] Connected to Central Database securely.\n";
    return true;
}

// --- 2. Cryptography ---
std::string encrypt_data(std::vector<unsigned char>& data) {
    unsigned char iv[12];
    RAND_bytes(iv, sizeof(iv)); 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    std::vector<unsigned char> ciphertext(data.size() + 16); 
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)ACTIVE_MASTER_KEY.c_str(), iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), tag, tag + 16);
    data = ciphertext; 
    EVP_CIPHER_CTX_free(ctx);
    std::stringstream ss;
    for(int i=0; i<12; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)iv[i];
    return ss.str();
}

bool decrypt_data(std::vector<unsigned char>& data, const std::string& iv_hex) {
    unsigned char iv[12];
    for (int i = 0; i < 12; ++i) {
        std::string byteString = iv_hex.substr(i * 2, 2);
        iv[i] = (unsigned char)strtol(byteString.c_str(), NULL, 16);
    }
    if (data.size() < 16) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    size_t ciphertext_len = data.size() - 16;
    std::vector<unsigned char> ciphertext(data.begin(), data.begin() + ciphertext_len);
    std::vector<unsigned char> tag(data.end() - 16, data.end());
    std::vector<unsigned char> plaintext(ciphertext_len);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)ACTIVE_MASTER_KEY.c_str(), iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        data = plaintext;
        return true;
    }
    return false; 
}

// --- 3. Peer Replication Engine ---
void replicate_to_peer(std::string filename, std::string iv_hex, std::vector<unsigned char> encrypted_data) {
    if (PEER_IP.empty()) return;
    std::cout << "[*] Replicating " << filename << " to peer in background...\n";
    
    CURL *curl = curl_easy_init();
    if (curl) {
        std::string url = "https://" + PEER_IP + ":8443/internal/replicate";
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, ("X-Filename: " + filename).c_str());
        headers = curl_slist_append(headers, ("X-IV: " + iv_hex).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/octet-stream");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encrypted_data.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, encrypted_data.size());

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) std::cout << "[+] Replication successful!\n";
        else std::cerr << "[-] Replication failed.\n";

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

// --- 4. Main Application ---
int main() {
    if (!fetch_master_key() || !init_db()) {
        std::cerr << "[-] Critical infrastructure unavailable.\n";
        return 1;
    }

    crow::SimpleApp app;

    // A. STANDARD UPLOAD ROUTE
    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        std::string owner = "test_user"; 
        std::string filename = req.get_header_value("X-Filename");
        if (filename.empty()) filename = "unnamed_upload.dat";

        std::vector<unsigned char> file_buffer(req.body.begin(), req.body.end());
        std::string iv_hex = encrypt_data(file_buffer);

        // Save locally
        std::string filepath = "storage/" + filename;
        std::ofstream outfile(filepath, std::ios::binary);
        outfile.write((char*)file_buffer.data(), file_buffer.size());
        outfile.close();

        // Log to DB
        std::string query = "INSERT INTO files (filename, owner_username, stored_on_node, encryption_iv) VALUES ('" 
                            + filename + "', '" + owner + "', '" + NODE_NAME + "', '" + iv_hex + "')";
        if (mysql_query(db_conn, query.c_str())) return crow::response(500, "Database error");

        // Fire and forget replication to the other node
        std::thread(replicate_to_peer, filename, iv_hex, file_buffer).detach();

        return crow::response(200, "File encrypted and stored securely.");
    });

    // B. INTERNAL REPLICATION ROUTE (Receives files from the peer)
    CROW_ROUTE(app, "/internal/replicate").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        std::string filename = req.get_header_value("X-Filename");
        std::string iv_hex = req.get_header_value("X-IV");
        if (filename.empty() || iv_hex.empty()) return crow::response(400, "Missing headers");

        // Save the raw encrypted data received from the peer directly to disk
        std::string filepath = "storage/" + filename;
        std::ofstream outfile(filepath, std::ios::binary);
        outfile.write(req.body.data(), req.body.size());
        outfile.close();

        // Log this node's copy to the DB
        std::string query = "INSERT INTO files (filename, owner_username, stored_on_node, encryption_iv) VALUES ('" 
                            + filename + "', 'test_user', '" + NODE_NAME + "', '" + iv_hex + "')";
        mysql_query(db_conn, query.c_str());

        return crow::response(200, "Replicated locally.");
    });

    // C. STANDARD DOWNLOAD ROUTE
    CROW_ROUTE(app, "/download").methods(crow::HTTPMethod::GET)([](const crow::request& req) {
        std::string filename = req.get_header_value("X-Filename");
        if (filename.empty()) return crow::response(400, "Missing X-Filename");

        std::string filepath = "storage/" + filename;
        std::ifstream infile(filepath, std::ios::binary);
        if (!infile) return crow::response(404, "File not found on this node.");
        std::vector<unsigned char> file_buffer((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
        infile.close();

        std::string query = "SELECT encryption_iv FROM files WHERE filename = '" + filename + "' AND stored_on_node = '" + NODE_NAME + "' ORDER BY id DESC LIMIT 1";
        if (mysql_query(db_conn, query.c_str())) return crow::response(500, "DB Error");
        
        MYSQL_RES *result = mysql_store_result(db_conn);
        if (!result || mysql_num_rows(result) == 0) {
            if(result) mysql_free_result(result);
            return crow::response(404, "File metadata not found.");
        }
        MYSQL_ROW row = mysql_fetch_row(result);
        std::string iv_hex = row[0];
        mysql_free_result(result);

        if (!decrypt_data(file_buffer, iv_hex)) return crow::response(403, "Decryption failed.");

        crow::response res(std::string(file_buffer.begin(), file_buffer.end()));
        res.add_header("Content-Type", "application/octet-stream");
        return res;
    });

    std::cout << "[*] Starting Storage Node on port 8443...\n";
    app.port(8443).bindaddr("0.0.0.0")
       .ssl_file("certs/internal_node.crt", "certs/internal_node.key")
       .multithreaded().run();

    mysql_close(db_conn);
    return 0;
}