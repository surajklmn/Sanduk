#include <iostream>
#include <fstream>
#include <string>
#include <vector>
void printWelcomeScreen()
{
  std::cout << "*******************************************" << std::endl;
  std::cout << "*            Welcome to Sanduk            *" << std::endl;
  std::cout << "*          Password Manager               *" << std::endl;
  std::cout << "*******************************************" << std::endl;
  std::cout << "*                                         *" << std::endl;
  std::cout << "*                1) Create User           *" << std::endl;
  std::cout << "*                2) Login                 *" << std::endl;
  std::cout << "*                                         *" << std::endl;
  std::cout << "*******************************************" << std::endl;
  std::cout << std::endl;
}
class Login {
  public:
    Login(const std::string& username, const std::string& password) : username_(username), password_(password) {}

    const std::string& getUsername() const { return username_; }
    const std::string& getPassword() const { return password_; }

  private:
    std::string username_;
    std::string password_;
};
int main()
{
  printWelcomeScreen();

    std::vector<Login> logins;
  // Open the logins.csv file
  std::ifstream loginsFile("logins.csv");

  // Read the logins from the file
  while (loginsFile.good()) {
    std::string username, password;
    loginsFile >> username >> password;

    // Create a new Login object and store it in a vector
    logins.push_back(Login(username, password));
  }

  // Close the file
  loginsFile.close();

  // Print the usernames and passwords
  for (const auto& login : logins) {
    std::cout << login.getUsername() << ": " << login.getPassword() << std::endl;
  }

  return 0;
}
