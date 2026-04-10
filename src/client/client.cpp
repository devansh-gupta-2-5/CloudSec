// g++ client.cpp -o client -I./include -lcurl
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <curl/curl.h>
#include "../server/include/crow_all.h" // Ensure you have this path correct!

// --- Configuration ---
// Change this to Machine 0's actual LAN IP so it works from Machine 3!
const std::string GATEWAY_URL = "https://10.70.69.63"; 

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

struct Response {
    std::string body;
    long code;
};

// --- HTTP Request Wrapper ---
Response send_request(const std::string &url, const std::string &method, const std::string &payload = "", const std::string &token = "", const std::string &filename_header = "") {
    CURL *curl = curl_easy_init();
    Response resp;
    if (curl) {
        struct curl_slist *headers = NULL;
        
        // If we are sending a file payload, we use application/octet-stream
        if (!filename_header.empty()) {
            headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
            std::string f_header = "X-Filename: " + filename_header;
            headers = curl_slist_append(headers, f_header.c_str());
        } else {
            headers = curl_slist_append(headers, "Content-Type: application/json");
        }

        if (!token.empty()) {
            std::string auth_header = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, auth_header.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
        
        // Bypass self-signed cert errors (equivalent to curl -k)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            // .data() and .size() handle raw binary file data perfectly safely in C++
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.data());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());
        } else if (method == "GET") {
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        }

        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return resp;
}

// --- File I/O Helpers ---
std::string read_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

bool write_file(const std::string& filepath, const std::string& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file) return false;
    file.write(data.data(), data.size());
    return true;
}

// --- Post-Login Menu ---
void user_dashboard(const std::string& username, const std::string& token) {
    while (true) {
        std::cout << "\n--- Welcome, " << username << " ---\n";
        std::cout << "1. Upload a File\n";
        std::cout << "2. Download a File\n";
        std::cout << "3. Logout\n";
        std::cout << "Choose an option: ";
        
        std::string choice;
        std::cin >> choice;

        if (choice == "3") {
            std::cout << "[*] Logged out.\n";
            break;
        }
        else if (choice == "1") {
            std::string filepath, dest_filename;
            std::cout << "Enter local path to file (e.g., ./my_doc.txt): ";
            std::cin >> filepath;
            std::cout << "Enter name to save as on cloud (e.g., doc.txt): ";
            std::cin >> dest_filename;

            std::string file_data = read_file(filepath);
            if (file_data.empty()) {
                std::cout << "[-] Could not read local file. Does it exist?\n";
                continue;
            }

            std::cout << "[*] Uploading " << file_data.size() << " bytes...\n";
            Response res = send_request(GATEWAY_URL + "/upload", "POST", file_data, token, dest_filename);
            
            if (res.code == 200) {
                std::cout << "[SUCCESS] File uploaded to cloud!\n";
            } else {
                std::cout << "[FAIL] Server responded with code: " << res.code << "\n" << res.body << "\n";
            }
        }
        else if (choice == "2") {
            std::string filename, dest_filepath;
            std::cout << "Enter filename to download from cloud: ";
            std::cin >> filename;
            std::cout << "Enter local path to save it to (e.g., ./downloaded.txt): ";
            std::cin >> dest_filepath;

            std::cout << "[*] Downloading...\n";
            // Note: We send the filename as a header to the /download endpoint
            Response res = send_request(GATEWAY_URL + "/download", "GET", "", token, filename);
            
            if (res.code == 200) {
                if (write_file(dest_filepath, res.body)) {
                    std::cout << "[SUCCESS] File saved to " << dest_filepath << "\n";
                } else {
                    std::cout << "[-] Failed to write to local disk.\n";
                }
            } else {
                std::cout << "[FAIL] Download failed. Code: " << res.code << "\n" << res.body << "\n";
            }
        }
    }
}

// --- Main Auth Loop ---
int main() {
    curl_global_init(CURL_GLOBAL_ALL);

    while (true) {
        std::cout << "\n========================\n";
        std::cout << "   CloudSec Terminal\n";
        std::cout << "========================\n";
        std::cout << "1. Login\n";
        std::cout << "2. Register New User\n";
        std::cout << "3. Exit\n";
        std::cout << "Choose an option: ";
        
        std::string choice;
        std::cin >> choice;

        if (choice == "3" || choice == "exit") break;

        if (choice == "2") {
            std::string user, pass;
            std::cout << "New Username: ";
            std::cin >> user;
            std::cout << "New Password: ";
            std::cin >> pass;

            std::string reg_json = "{\"username\":\"" + user + "\", \"password\":\"" + pass + "\"}";
            // Note: You will need to build the /register route on the servers eventually!
            Response res = send_request(GATEWAY_URL + "/register", "POST", reg_json);

            if (res.code == 201 || res.code == 200) {
                std::cout << "[SUCCESS] Registered successfully.\n";
            } else {
                std::cout << "[FAIL] Code: " << res.code << " | " << res.body << "\n";
            }
        }
        else if (choice == "1") {
            std::string user, pass;
            std::cout << "Username: ";
            std::cin >> user;
            std::cout << "Password: ";
            std::cin >> pass;

            // FAKE LOGIN BYPASS FOR NOW:
            // Since your C++ node_server doesn't have a /login route right now, 
            // we will bypass it so you can test the upload/download menu.
            std::string fake_token = "fake_jwt_token_for_now";
            user_dashboard(user, fake_token);
        }
    }

    curl_global_cleanup();
    return 0;
}