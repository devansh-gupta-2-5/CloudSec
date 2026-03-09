// src/monitoring/monitor.cpp
// g++ monitor.cpp -o monitor -lcurl
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <thread>
#include <curl/curl.h>

const std::string AUTH_LOG_FILE = "../../logs/auth.log";
const std::string THREATS_LOG_FILE = "../../logs/threats.log";
const std::string MITIGATION_LOG_FILE = "../../logs/mitigation.log"; // Added mitigation log
const std::string BAN_URL = "http://127.0.0.1:8080/internal/ban";
const int FAIL_LIMIT = 5;
const int TIME_WINDOW_SEC = 60;

std::unordered_map<std::string, std::vector<std::time_t>> failed_attempts;

// Helper to log Monitor detections to any file
void log_event(const std::string& file_path, const std::string& status, const std::string& ip, const std::string& event) {
    std::ofstream log_file(file_path, std::ios_base::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::string time_str = std::ctime(&now);
        time_str.pop_back();
        log_file << "[" << time_str << "] IP: " << ip << " | Status: " << status << " | Event: " << event << "\n";
    } else {
        std::cerr << "[ERROR] Could not open log file: " << file_path << "\n";
    }
}

// Dummy callback to stop libcurl from printing the server's raw HTTP response to the terminal
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb;
}

// C++ Libcurl function to send the ban POST request
void trigger_ban(const std::string& ip) {
    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    
    if(curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        std::string json_data = "{\"ip\": \"" + ip + "\"}";
        
        curl_easy_setopt(curl, CURLOPT_URL, BAN_URL.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback); // Suppress raw output
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            std::cerr << "\n[MONITOR] Failed to ban IP: " << curl_easy_strerror(res) << "\n";
        } else {
            std::cout << "\n[MITIGATION] Successfully triggered ban for IP: " << ip << "\n";
            // 1. Log the threat identification
            log_event(THREATS_LOG_FILE, "MONITOR_ALERT", ip, "Brute-force attack detected (5+ failed logins).");
            // 2. Log the mitigation action
            log_event(MITIGATION_LOG_FILE, "ACTION_TAKEN", ip, "Monitor automatically triggered application-layer ban.");
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

int main() {
    std::cout << "[*] Starting C++ Security Monitor Daemon...\n";
    std::cout << "[*] Tailing " << AUTH_LOG_FILE << "\n";

    std::ifstream file(AUTH_LOG_FILE);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << AUTH_LOG_FILE << ". Did the app server create it yet?\n";
        return 1;
    }

    // Jump to the end of the file
    file.seekg(0, std::ios::end);

    std::regex log_pattern(R"(\[.*?\] IP: (.*?) \| Status: (SUCCESS|FAILED))");

    while (true) {
        std::string line;
        if (std::getline(file, line)) {
            std::smatch match;
            if (std::regex_search(line, match, log_pattern)) {
                std::string ip = match[1].str();
                std::string status = match[2].str();

                if (status == "FAILED") {
                    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    failed_attempts[ip].push_back(now);

                    // Clean up old timestamps outside the 60s window
                    auto& times = failed_attempts[ip];
                    times.erase(std::remove_if(times.begin(), times.end(), 
                        [now](std::time_t t) { return std::difftime(now, t) > TIME_WINDOW_SEC; }), times.end());

                    std::cout << "[MONITOR] Warning: Failed login from " << ip << " (" << times.size() << "/" << FAIL_LIMIT << ")\n";

                    if (times.size() == FAIL_LIMIT) {
                        trigger_ban(ip);
                        // We intentionally don't clear the times array here so it doesn't spam ban requests 
                        // if the attacker keeps trying while already banned.
                    }
                }
            }
        } else {
            // End of file reached, clear EOF flag and sleep briefly before checking again
            file.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    return 0;
}