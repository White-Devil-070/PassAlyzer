// Password Strength and Pwned Password Checker (WinINet ANSI version)
#include <bits/stdc++.h>
#include <cctype>
#include <openssl/sha.h>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

using namespace std;

// Helper to convert SHA1 hash to uppercase hex string
string sha1Hex(const string &input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << uppercase << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Perform HTTPS GET using WinINet (ANSI version)
string httpGET(const string &host, const string &path) {
    HINTERNET hInternet = InternetOpenA("PwnedPasswordChecker", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return "[InternetOpen failed]";

    HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT,
                                          NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "[InternetConnect failed]";
    }

    const char* acceptTypes[] = {"/", NULL};
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path.c_str(), NULL,
                                          NULL, acceptTypes,
                                          INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);

    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "[HttpOpenRequest failed]";
    }

    BOOL sent = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
    if (!sent) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "[HttpSendRequest failed]";
    }

    string response;
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

// Check if password is found in HaveIBeenPwned API
string checkPwnedPassword(const string &password) {
    string sha1 = sha1Hex(password);
    string prefix = sha1.substr(0, 5);
    string suffix = sha1.substr(5);

    string urlPath = "/range/" + prefix;
    string response = httpGET("api.pwnedpasswords.com", urlPath);

    if (response.rfind("[", 0) == 0) {
        return "Could not check for breaches (Error: " + response + ")";
    }

    istringstream stream(response);
    string line;
    while (getline(stream, line)) {
        if (line.substr(0, suffix.size()) == suffix) {
            return "WARNING: This password has been found in a data breach!";
        }
    }
    return "Password not found in known breaches.";
}

// Check character composition strength
string CaseCheck(string str) {
    int Upp = 0, Low = 0, Dig = 0, Punct = 0;

    for (int i = 0; i < (int)str.length(); i++) {
        if (islower(str[i])) Low = 1;
        else if (isupper(str[i])) Upp = 1;
        else if (isdigit(str[i])) Dig = 1;
        else if (ispunct(str[i])) Punct = 1;
    }

    if (Upp == 1 && Low == 1 && Dig == 1 && Punct == 1)
        return "Strong";
    else if (Upp == 1 && Low == 1 && Dig == 1 && Punct == 0)
        return "Moderate (Add at least one special character)";
    else if (Upp == 1 && Low == 1 && Dig == 0 && Punct == 1)
        return "Moderate (Add at least one digit)";
    else if (Upp == 1 && Low == 0 && Dig == 1 && Punct == 1)
        return "Moderate (Add at least one lowercase letter)";
    else if (Upp == 0 && Low == 1 && Dig == 1 && Punct == 1)
        return "Moderate (Add at least one uppercase letter)";
    else if (Upp == 1 && Low == 1 && Dig == 0 && Punct == 0)
        return "Weak (Add digits and special characters)";
    else if (Upp == 1 && Low == 0 && Dig == 1 && Punct == 0)
        return "Weak (Add lowercase letters and special characters)";
    else if (Upp == 1 && Low == 0 && Dig == 0 && Punct == 1)
        return "Weak (Add lowercase letters and digits)";
    else if (Upp == 0 && Low == 1 && Dig == 1 && Punct == 0)
        return "Weak (Add uppercase letters and special characters)";
    else if (Upp == 0 && Low == 1 && Dig == 0 && Punct == 1)
        return "Weak (Add uppercase letters and digits)";
    else if (Upp == 0 && Low == 0 && Dig == 1 && Punct == 1)
        return "Weak (Add letters: uppercase and lowercase)";
    else if (Upp == 1 && Low == 0 && Dig == 0 && Punct == 0)
        return "Very Weak (Only uppercase letters)";
    else if (Upp == 0 && Low == 1 && Dig == 0 && Punct == 0)
        return "Very Weak (Only lowercase letters)";
    else if (Upp == 0 && Low == 0 && Dig == 1 && Punct == 0)
        return "Very Weak (Only digits)";
    else if (Upp == 0 && Low == 0 && Dig == 0 && Punct == 1)
        return "Very Weak (Only special characters)";
    else
        return "Very Weak (Empty or invalid characters)";
}

// Main checker that also validates length
string StrengthChecker(string str) {
    int length = (int)str.length();

    if (length < 8)
        return "Too Weak (Password should contain at least 8 characters)";

    return CaseCheck(str);
}

int main() {
    string str;
    cout << "Enter the password to check strength: ";
    cin >> str;

    string strength = StrengthChecker(str);
    cout << "Password Strength: " << strength << endl;

    string breachResult = checkPwnedPassword(str);
    cout << breachResult << endl;
system("pause");
    return 0;
}
// compile with: g++ main.cpp -o PassAlyzer -lwininet -lssl -lcrypto
// run with: PassAlyzer.exe
// Note: This code uses WinINet for HTTPS requests, which is specific to Windows.