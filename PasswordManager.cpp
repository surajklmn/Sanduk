#include <iostream>
#include <map>
#include <string>
#include <cstdlib>

class PasswordManager {
private:
    std::map<std::string, std::string> passwords;
    std::string masterPassword;

public:
    PasswordManager(const std::string& masterPassword) : masterPassword(masterPassword) {}

    bool authenticate() {
        std::string enteredPassword;
        std::cout << "Enter master password: ";
        std::cin >> enteredPassword;

        return enteredPassword == masterPassword;
    }

    void savePassword(const std::string& url, const std::string& password) {
        passwords[url] = password;
        std::cout << "Password saved for " << url << std::endl;
    }

    void retrievePassword(const std::string& url) {
        auto it = passwords.find(url);
        if (it != passwords.end()) {
            std::cout << "Password for " << url << ": " << it->second << std::endl;
        } else {
            std::cout << "Password not found for " << url << std::endl;
        }
    }
};

int main() {
    std::string masterPassword;
    std::cout << "Set master password: ";
    std::cin >> masterPassword;

    PasswordManager passwordManager(masterPassword);

    if (!passwordManager.authenticate()) {
        std::cout << "Authentication failed. Exiting." << std::endl;
        return 1;
    }

    char choice;
    do {
        std::cout << "\nOptions:\n";
        std::cout << "1. Save Password\n";
        std::cout << "2. Retrieve Password\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter choice: ";
        std::cin >> choice;

        switch (choice) {
            case '1': {
                std::string url, password;
                std::cout << "Enter URL: ";
                std::cin >> url;
                std::cout << "Enter password: ";
                std::cin >> password;
                passwordManager.savePassword(url, password);
                break;
            }
            case '2': {
                std::string url;
                std::cout << "Enter URL: ";
                std::cin >> url;
                passwordManager.retrievePassword(url);
                break;
            }
            case '3':
                std::cout << "Exiting.\n";
                break;
            default:
                std::cout << "Invalid choice. Try again.\n";
        }
    } while (choice != '3');

    return 0;
}

