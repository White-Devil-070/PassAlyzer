// Password Strength and Pwned Password Checker (WinINet ANSI version)
#include <bits/stdc++.h>
#include <cctype>


using namespace std;

string checkLocalPwnedPasswords(const string& password, const string& filename = "./pwnedpasswords.txt") {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << " Could not open local pwned password file: " << filename << endl;
        return " Could not open local pwned password file: ";
    }

    string line;
    while (getline(file, line)) {
        if (line == password) {
            return "WARNING: This password has been found in a local breach database!";
        }
    }

    return " Good news: This password was not found in the local breach list.";
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

    string breachResult = checkLocalPwnedPasswords(str);
    cout << breachResult << endl;
system("pause");
    return 0;
}
// This code checks the strength of a password based on its character composition and length.
// It also checks if the password has been found in a local breach database.