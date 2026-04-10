// node_server.cpp
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

const std::string MACHINE_0_IP = "10.61.56.1"; // CHANGE THIS
const std::string NODE_NAME = "node_ubuntu"; // UNIQUE TO MACHINE 2

std::string ACTIVE_MASTER_KEY = "";
MYSQL *db_conn;

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

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

    if (res != CURLE_OK) {
        std::cerr << "[-] Failed to reach KMS.\n";
        return false;
    }

    auto json = crow::json::load(resp);
    if (!json || !json.has("master_key")) return false;
    
    ACTIVE_MASTER_KEY = json["master_key"].s();
    std::cout << "[+] Master Key acquired and loaded into memory.\n";
    return true;
}

bool init_db() {
    db_conn = mysql_init(NULL);
    mysql_ssl_set(db_conn, NULL, NULL, "certs/rootCA.crt", NULL, NULL);
    my_bool my_false = 0;
    mysql_options(db_conn, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &my_false);

    if (mysql_real_connect(db_conn, MACHINE_0_IP.c_str(), "cloudnode", "securepass123", "cloudsec_db", 3306, NULL, CLIENT_SSL) == NULL) {
        std::cerr << "[-] Database connection failed: " << mysql_error(db_conn) << "\n";
        return false;
    }
    std::cout << "[+] Connected to Central Database securely.\n";
    return true;
}

std::string encrypt_data(std::vector<unsigned char>& data) {
    unsigned char iv[12];
    RAND_bytes(iv, sizeof(iv)); 

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
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

int main() {
    if (!fetch_master_key() || !init_db()) {
        std::cerr << "[-] Critical infrastructure unavailable. Shutting down.\n";
        return 1;
    }

    crow::SimpleApp app;

    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        std::string owner = "test_user"; 
        std::string filename = "uploaded_file.txt";

        std::vector<unsigned char> file_buffer(req.body.begin(), req.body.end());
        
        std::string iv_hex = encrypt_data(file_buffer);

        std::string filepath = "storage/" + filename;
        std::ofstream outfile(filepath, std::ios::binary);
        outfile.write((char*)file_buffer.data(), file_buffer.size());
        outfile.close();

        std::string query = "INSERT INTO files (filename, owner_username, stored_on_node, encryption_iv) VALUES ('" 
                            + filename + "', '" + owner + "', '" + NODE_NAME + "', '" + iv_hex + "')";
        if (mysql_query(db_conn, query.c_str())) {
            return crow::response(500, "Database error");
        }

        return crow::response(200, "File encrypted and stored securely.");
    });

    std::cout << "[*] Starting Storage Node on port 8443...\n";
    app.port(8443).bindaddr("0.0.0.0")
       .ssl_file("certs/internal_node.crt", "certs/internal_node.key")
       .multithreaded().run();

    mysql_close(db_conn);
    return 0;
}