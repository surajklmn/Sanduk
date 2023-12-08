#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "global.h"

class UserManager;

namespace Utility
{
  std::string generateUniqueId()
  {
    std::vector<char> buffer(16);
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int> distribution(0, 255);

    for (char &elem : buffer)
    {
      elem = static_cast<char>(distribution(engine));
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char elem : buffer)
    {
      oss << std::setw(2) << static_cast<unsigned>(elem);
    }

    return oss.str();
  }

  std::string generateSalt(size_t saltSize)
  {
    std::vector<unsigned char> salt(saltSize);
    if (RAND_bytes(salt.data(), static_cast<int>(saltSize)) != 1)
    {
      // Handle error when generating random bytes
      throw std::runtime_error("Error generating random bytes for salt");
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char elem : salt)
    {
      oss << std::setw(2) << static_cast<unsigned>(elem);
    }

    return oss.str();
  }

  std::string hashString(const std::string &input, const std::string &salt)
  {
    std::string saltedInput = salt + input;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(saltedInput.c_str()), saltedInput.length(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      oss << std::setw(2) << static_cast<unsigned>(hash[i]);
    }

    return oss.str();
  }
}

class CustomException : public std::runtime_error
{
public:
  explicit CustomException(const std::string &message) : std::runtime_error(message) {}
};

class User
{
  std::string id;
  std::string username;
  std::string password;
  std::string salt;

  friend UserManager;
  User(const std::string &id, const std::string &username, const std::string &password, const std::string &salt) : id(id), username(username), password(password), salt(salt) {}

public:
  User(std::string username, std::string password, std::string confirmPassword)
  {
    this->id = Utility::generateUniqueId();

    if (username.length() < 5 || username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_") != std::string::npos)
    {
      throw CustomException("Invalid username. It must be at least 5 characters long and can only contain letters, numbers, and underscores.");
    }

    this->username = username;

    if (password.length() < 8)
    {
      throw CustomException("Invalid password. It must be at least 8 characters long.");
    }

    if (password != confirmPassword)
    {
      throw CustomException("Password and confirm password do not match.");
    }

    this->salt = Utility::generateSalt(SALT_SIZE);

    this->password = Utility::hashString(password, this->salt);
  }

  std::string
  getId() const
  {
    return this->id;
  }

  std::string getUsername() const
  {
    return this->username;
  }

  std::string getPassword() const
  {
    return this->password;
  }

  std::string getSalt() const
  {
    return this->salt;
  }

  void updatePassword(const std::string &newPassword)
  {
    this->password = Utility::hashString(newPassword, this->salt);
  }

  void updateUsername(const std::string &newUsername)
  {
    this->username = newUsername;
  }
};

class UserManager
{
  std::string filename;
  std::vector<User> users;

public:
  UserManager(const std::string &filename) : filename(filename)
  {
    std::ifstream file(this->filename);
    if (!file.is_open())
    {
      std::ofstream createFile(this->filename);
      if (!createFile.is_open())
      {
        throw CustomException("Error creating file.");
      }
      createFile.close();
    }
    else
    {
      file.close();
    }

    this->loadUsers();
  }

  void loadUsers()
  {
    std::ifstream file(this->filename);

    if (!file.is_open())
    {
      throw CustomException("Error opening file.");
    }

    std::string line;

    while (std::getline(file, line))
    {
      std::istringstream iss(line);
      std::string id, username, password, salt;

      std::getline(iss, id, ',');
      std::getline(iss, username, ',');
      std::getline(iss, password, ',');
      std::getline(iss, salt, ',');

      this->users.push_back(User(id, username, password, salt));
    }
  }

  void saveUsers() const
  {
    std::ofstream file(this->filename);

    if (!file.is_open())
    {
      throw CustomException("Error opening file.");
    }

    for (const User &user : this->users)
    {
      file << user.getId() << "," << user.getUsername() << "," << user.getPassword() << "," << user.getSalt() << "\n";
    }

    file.close();
  }

  void addUser(const User &user)
  {
    this->users.push_back(user);
  }

  bool isUsernameTaken(const std::string &username) const
  {
    for (const User &user : this->users)
    {
      if (user.getUsername() == username)
      {
        return true;
      }
    }

    return false;
  }

  const User &getUser(const std::string &id) const
  {
    for (const User &user : this->users)
    {
      if (user.getId() == id)
      {
        return user;
      }
    }

    throw CustomException("User not found.");
  }

  const User &getUserByUsername(const std::string &username) const
  {
    for (const User &user : this->users)
    {
      if (user.getUsername() == username)
      {
        return user;
      }
    }

    throw CustomException("User not found.");
  }
};

class UserInterface
{
  static const int MAX_WIDTH = 50;
  static const char DEFAULT_LINE_CHAR = '*';

  static void printLine(char c)
  {
    for (int i = 0; i < MAX_WIDTH; i++)
    {
      std::cout << c;
    }
    std::cout << std::endl;
  }

  static void printCenteredText(const std::string &text)
  {
    int textLength = text.length();
    int padding = (MAX_WIDTH - textLength) / 2;

    for (int i = 0; i < padding; i++)
    {
      std::cout << ' ';
    }

    std::cout << text;

    for (int i = 0; i < padding; i++)
    {
      std::cout << ' ';
    }

    std::cout << std::endl;
  }

  static void printText(const std::string &text)
  {
    std::cout << text << std::endl;
  }

public:
  static void printWelcomeScreen()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Welcome to Sanduk");
    printCenteredText("Your Password Manager");
    printLine(DEFAULT_LINE_CHAR);
    printText("1) Create User");
    printText("2) Login");
    printLine(DEFAULT_LINE_CHAR);
    std::cout << std::endl;
  }

  static void printCreateUserScreen()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Create User");
    printLine(DEFAULT_LINE_CHAR);
  }

  static void printLoginScreen()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Login");
    printLine(DEFAULT_LINE_CHAR);
  }
};

int main()
{
  UserInterface::printWelcomeScreen();

  int choice;
  std::cout << "Enter your choice: ";
  std::cin >> choice;

  if (choice == 1)
  {
    std::string username, password, confirmPassword;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;
    std::cout << "Confirm password: ";
    std::cin >> confirmPassword;

    try
    {
      UserManager userManager("users.csv");

      if (userManager.isUsernameTaken(username))
      {
        throw CustomException("Username already taken.");
      }

      User user(username, password, confirmPassword);
      userManager.addUser(user);
      userManager.saveUsers();
      std::cout << "User created successfully." << std::endl;
    }
    catch (const CustomException &e)
    {
      std::cout << e.what() << std::endl;
    }
  }
  else if (choice == 2)
  {
    std::string username, password;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    try
    {
      UserManager userManager("users.csv");
      const User &user = userManager.getUserByUsername(username);
      if (user.getPassword() == Utility::hashString(password, user.getSalt()))
      {
        std::cout << "Login successful." << std::endl;
      }
      else
      {
        std::cout << "Login failed." << std::endl;
      }
    }
    catch (const CustomException &e)
    {
      std::cout << e.what() << std::endl;
    }
  }
  else
  {
    std::cout << "Invalid choice." << std::endl;
  }

  return 0;
}
