// g++ client.cpp -o client -I./include -lcurl
#include <iostream>
#include <string>
#include <curl/curl.h>
#include "../server/include/crow_all.h" // Using Crow's JSON parser for convenience

// Helper to handle the response from Nginx
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

struct Response
{
    std::string body;
    long code;
};

Response send_request(const std::string &url, const std::string &method, const std::string &payload = "", const std::string &token = "")
{
    CURL *curl = curl_easy_init();
    Response resp;
    if (curl)
    {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        if (!token.empty())
        {
            std::string auth_header = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, auth_header.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Don't verify the certificate
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // Don't verify the hostname

        if (method == "POST")
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        }

        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return resp;
}

int main()
{
    curl_global_init(CURL_GLOBAL_ALL);
    std::string gateway = "http://127.0.0.1:8081"; // Pointing to Nginx

    while (true)
    {
        std::string user, pass;
        std::cout << "\n========================\n";
        std::cout << "   CloudSec Auth CLI\n";
        std::cout << "========================\n";
        std::cout << "Username (or 'exit'): ";
        std::cin >> user;
        if (user == "exit")
            break;

        std::cout << "Password: ";
        std::cin >> pass;

        std::string login_json = "{\"username\":\"" + user + "\", \"password\":\"" + pass + "\"}";
        Response res = send_request(gateway + "/login", "POST", login_json);

        if (res.code == 200)
        {
            auto out = crow::json::load(res.body);
            std::string token = out["token"].s();
            std::cout << "[SUCCESS] Logged in as: " << user << "\n";

            // If admin, show extra options
            if (user == "admin")
            {
                char choice;
                std::cout << "Would you like to add a new user? (y/n): ";
                std::cin >> choice;
                if (choice == 'y')
                {
                    std::string n_user, n_pass, n_role;
                    std::cout << "New Username: ";
                    std::cin >> n_user;
                    std::cout << "New Password: ";
                    std::cin >> n_pass;
                    std::cout << "Role (user/moderator): ";
                    std::cin >> n_role;

                    std::string body = "{\"username\":\"" + n_user + "\",\"password\":\"" + n_pass + "\",\"role\":\"" + n_role + "\"}";
                    Response add_res = send_request(gateway + "/admin/add_user", "POST", body, token);
                    std::cout << "[STATUS] " << add_res.body << "\n";
                }
            }
        }
        else
        {
            std::cout << "[FAIL] Code: " << res.code << " | " << res.body << "\n";
        }
    }

    curl_global_cleanup();
    return 0;
}