#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "global.h"
// std::string encryptPassword(const std::string &password, const std::string &key)
// {
//   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

//   // Set up encryption context
//   EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char *>(key.c_str()), NULL);

//   int len = password.length() + EVP_MAX_BLOCK_LENGTH;
//   unsigned char *cipherText = new unsigned char[len];

//   // Encrypt the password
//   EVP_EncryptUpdate(ctx, cipherText, &len, reinterpret_cast<const unsigned char *>(password.c_str()), password.length());
//   int cipherLen = len;

//   EVP_EncryptFinal_ex(ctx, cipherText + cipherLen, &len);
//   cipherLen += len;

//   // Cleanup
//   EVP_CIPHER_CTX_free(ctx);

//   // Convert to hexadecimal string
//   std::ostringstream oss;
//   for (int i = 0; i < cipherLen; ++i)
//     oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(cipherText[i]);

//   delete[] cipherText;

//   return oss.str();
// }

// // Function to decrypt a password
// std::string decryptPassword(const std::string &encryptedPassword, const std::string &key)
// {
//   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

//   // Set up decryption context
//   EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char *>(key.c_str()), NULL);

//   int len = encryptedPassword.length() / 2;
//   unsigned char *decryptedText = new unsigned char[len];

//   // Convert from hexadecimal string to binary
//   for (int i = 0; i < len; ++i)
//     sscanf(encryptedPassword.substr(i * 2, 2).c_str(), "%02x", &decryptedText[i]);

//   // Decrypt the password
//   EVP_DecryptUpdate(ctx, decryptedText, &len, decryptedText, len);
//   int decryptedLen = len;

//   EVP_DecryptFinal_ex(ctx, decryptedText + decryptedLen, &len);
//   decryptedLen += len;

//   // Cleanup
//   EVP_CIPHER_CTX_free(ctx);

//   return std::string(reinterpret_cast<char *>(decryptedText), decryptedLen);
// }

class UserManager;
class LoginInfoManager;

std::string currentUserId = "";
std::string currentUserUsername = "";

namespace Utility
{
  std::string generateSimpleId()
  {
    std::vector<char> buffer(8);
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

  void exitProgram()
  {
    std::cout << "Exiting..." << '\n';
    exit(0);
  }

  void clearInputBuffer()
  {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
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

  std::string getId() const
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

class LoginInfo
{
  std::string id;
  std::string website;
  std::string username;
  std::string password;
  std::string userId;

  friend LoginInfoManager;
  LoginInfo(const std::string &id, const std::string &website, const std::string &username, const std::string &password, const std::string &userId) : id(id), website(website), username(username), password(password), userId(userId) {}

public:
  LoginInfo(std::string website, std::string username, std::string password, std::string userId)
  {
    this->id = Utility::generateSimpleId();
    this->website = website;
    this->username = username;
    this->password = password;
    this->userId = userId;
  }

  std::string getId() const
  {
    return this->id;
  }

  std::string getWebsite() const
  {
    return this->website;
  }

  std::string getUsername() const
  {
    return this->username;
  }

  std::string getPassword() const
  {
    return this->password;
  }

  std::string getUserId() const
  {
    return this->userId;
  }

  void updatePassword(const std::string &newPassword)
  {
    this->password = newPassword;
  }

  void updateUsername(const std::string &newUsername)
  {
    this->username = newUsername;
  }

  void updateWebsite(const std::string &newWebsite)
  {
    this->website = newWebsite;
  }
  // std::string getEncryptedPassword(const std::string &key) const
  // {
  //   return encryptPassword(password, key);
  // }

  // void setEncryptedPassword(const std::string &encryptedPassword, const std::string &key)
  // {
  //   password = decryptPassword(encryptedPassword, key);
  // }
};

class LoginInfoManager
{
  std::string filename;
  std::vector<LoginInfo> loginInfos;

public:
  LoginInfoManager(std::string filename) : filename(filename)
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

    this->loadLoginInfos();
  }

  void loadLoginInfos()
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
      std::string id, website, username, password, userId;

      std::getline(iss, id, ',');
      std::getline(iss, website, ',');
      std::getline(iss, username, ',');
      std::getline(iss, password, ',');
      std::getline(iss, userId, ',');

      this->loginInfos.push_back(LoginInfo(id, website, username, password, userId));
    }
  }

  void addLoginInfo(const LoginInfo &loginInfo)
  {
    this->loginInfos.push_back(loginInfo);
  }

  void saveLoginInfos() const
  {
    std::ofstream file(this->filename);

    if (!file.is_open())
    {
      throw CustomException("Error opening file.");
    }

    for (const LoginInfo &loginInfo : this->loginInfos)
    {
      file << loginInfo.getId() << "," << loginInfo.getWebsite() << "," << loginInfo.getUsername() << "," << loginInfo.getPassword() << "," << loginInfo.getUserId() << "\n";
    }

    file.close();
  }
  std::vector<LoginInfo> searchLoginInfos(const std::string &website) const
  {
    std::vector<LoginInfo> result;

    for (const LoginInfo &loginInfo : this->loginInfos)
    {
      if (loginInfo.getWebsite() == website)
      {
        result.push_back(loginInfo);
      }
    }

    return result;
  }
  std::vector<LoginInfo> getAllSavedWebsite(const std::string &userId) const
  {
    std::vector<LoginInfo> result;

    for (const LoginInfo &loginInfo : this->loginInfos)
    {
      if (loginInfo.getUserId() == userId)
      {
        result.push_back(loginInfo);
      }
    }

    return result;
  }
};

class UserInterface
{
protected:
  static const int MAX_WIDTH = 50;
  static const char DEFAULT_LINE_CHAR = '*';

public:
  static void printLine(char c = DEFAULT_LINE_CHAR)
  {
    for (int i = 0; i < MAX_WIDTH; i++)
    {
      std::cout << c;
    }
    std::cout << '\n';
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

    std::cout << '\n';
  }

  static void printText(const std::string &text, bool newLine = true)
  {
    std::cout << text << (newLine ? '\n' : ' ');
  }

  static void printWelcomeScreen()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Welcome to Sanduk");
    printCenteredText("Your Password Manager");
    printLine(DEFAULT_LINE_CHAR);
    printText("1) Create User");
    printText("2) Login");
    printLine(DEFAULT_LINE_CHAR);
    std::cout << '\n';
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

class MainMenuInterface : public UserInterface
{
  int choice;
  std::string website, username, password;

  void displayHeading()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Main Menu");
    printLine(DEFAULT_LINE_CHAR);
  }

  void displayMainMenu()
  {
    printText("1) Add Login");
    printText("2) List all logins");
    printText("3) Search Logins");
    printText("4) Exit");
  }

  void askChoice()
  {
    do
    {
      printText("Enter your choice: ", false);
      std::cin >> this->choice;

      if (std::cin.fail() || choice < 1 || choice > 5)
      {
        Utility::clearInputBuffer();
        printText("Invalid choice. Please try again");
      }
      else
      {
        break;
      }
    } while (true);
  }

  void handleChoice()
  {
    try
    {
      if (this->choice == 3)
      {
        printText("Enter website: ", false);
        std::cin >> this->website;

        LoginInfoManager loginInfoManager("loginInfos.csv");
        std::vector<LoginInfo> loginInfos = loginInfoManager.searchLoginInfos(this->website);

        if (loginInfos.empty())
        {
          printText("No logins found.");
        }
        else
        {
          printText("Logins found: ");
          for (const LoginInfo &loginInfo : loginInfos)
          {
            printText("Website: " + loginInfo.getWebsite());
            printText("Username: " + loginInfo.getUsername());
            printText("Password: " + loginInfo.getPassword());
            printText("");
          }
        }
        this->run();
      }
      else if (this->choice == 2)
      {
        LoginInfoManager loginInfoManager("loginInfos.csv");
        std::vector<LoginInfo> loginInfos = loginInfoManager.getAllSavedWebsite(currentUserId);
        printText("Existing websites:");
        for (const LoginInfo &loginInfo : loginInfos)
        {
          printText(loginInfo.getWebsite());
        }
        this->run();
      }
      else if (this->choice == 1)
      {
        // add login, ask website, username, password
        printText("Enter website: ", false);
        std::cin >> this->website;
        printText("Enter username: ", false);
        std::cin >> this->username;
        printText("Enter password: ", false);
        std::cin >> this->password;

        LoginInfoManager loginInfoManager("loginInfos.csv");
        loginInfoManager.addLoginInfo(LoginInfo(this->website, this->username, this->password, currentUserId));
        loginInfoManager.saveLoginInfos();
        printText("Login added successfully.");

        this->run();
      }
      else if (this->choice == 4)
      {
        Utility::exitProgram();
      }
    }
    catch (const std::exception &e)
    {
      printText(e.what());
      this->run(false);
    }
  }

public:
  void run(bool showHeading = true)
  {
    if (showHeading)
      displayHeading();

    try
    {
      displayMainMenu();
      askChoice();
      handleChoice();
    }
    catch (const std::exception &e)
    {
      printText(e.what());
      this->run(false);
    }
  }
};

class CreateUserInterface : public UserInterface
{
  std::string username, password, confirmPassword;

  void displayHeading()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Create User");
    printLine(DEFAULT_LINE_CHAR);
  }

  void askCredentials()
  {
    printText("Enter username: ", false);
    std::cin >> this->username;
    printText("Enter password: ", false);
    std::cin >> this->password;
    printText("Confirm password: ", false);
    std::cin >> this->confirmPassword;
  }

public:
  void run(bool showHeading = true)
  {
    if (showHeading)
      displayHeading();

    askCredentials();

    try
    {
      UserManager userManager("users.csv");

      if (userManager.isUsernameTaken(this->username))
      {
        throw CustomException("Username already taken.");
      }

      User user(this->username, this->password, this->confirmPassword);
      userManager.addUser(user);
      userManager.saveUsers();
      printText("User created successfully. Re-run the program to login");
    }
    catch (const CustomException &e)
    {
      printText(e.what());
      this->run(false);
    }
  }
};

class LoginInterface : public UserInterface
{
  std::string username, password;

  void displayHeading()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Login");
    printLine(DEFAULT_LINE_CHAR);
  }

  void askCredentials()
  {
    printText("Enter username: ", false);
    std::cin >> this->username;
    printText("Enter password: ", false);
    std::cin >> this->password;
  }

public:
  void run(bool showHeading = true)
  {
    if (showHeading)
      displayHeading();

    askCredentials();

    try
    {
      UserManager userManager("users.csv");
      const User &user = userManager.getUserByUsername(this->username);
      if (user.getPassword() == Utility::hashString(this->password, user.getSalt()))
      {
        currentUserId = user.getId();
        currentUserUsername = user.getUsername();
        printText("Login successful.");

        MainMenuInterface mainMenuInterface;
        mainMenuInterface.run();
      }
      else
      {
        throw CustomException("Invalid username or password.");
      }
    }
    catch (const CustomException &e)
    {
      printText(e.what());
      this->run(false);
    }
  }
};

class WelcomeInterface : public UserInterface
{
  int choice;

  void displayHeading()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Welcome to Sanduk");
    printCenteredText("Your Password Manager");
    printLine(DEFAULT_LINE_CHAR);
  }

  void displayMenu()
  {
    printText("1) Create User");
    printText("2) Login");
    printText("3) Exit");
  }

  void askChoice()
  {
    do
    {
      printText("Enter your choice: ", false);
      std::cin >> this->choice;

      if (std::cin.fail() || choice < 1 || choice > 3)
      {
        Utility::clearInputBuffer();
        printText("Invalid choice. Please try again");
      }
      else
      {
        break;
      }
    } while (true);
  }

  void handleChoice()
  {
    if (this->choice == 1)
    {
      CreateUserInterface createUserInterface;
      createUserInterface.run();
    }
    else if (this->choice == 2)
    {
      LoginInterface loginInterface;
      loginInterface.run();
    }
    else if (this->choice == 3)
    {
      Utility::exitProgram();
    }
  }

public:
  void run()
  {
    displayHeading();
    displayMenu();
    askChoice();
    handleChoice();
  }
};

class App
{
public:
  void run()
  {
    WelcomeInterface WelcomeInterface;
    WelcomeInterface.run();
  }
};

int main()
{
  App app;
  app.run();

  return 0;
}