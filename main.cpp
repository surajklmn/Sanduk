#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <ostream>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <string>

const int SALT_SIZE = 18;

class UserManager;
class LoginInfoManager;

std::string currentUserId = "";
std::string currentUserUsername = "";
std::string currentMasterPassword = "";

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

  std::string bytesToHexString(const std::vector<uint8_t> &bytes)
  {
    std::stringstream stream;
    for (const auto &byte : bytes)
    {
      stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return stream.str();
  }

  std::vector<uint8_t> hexStringToBytes(const std::string &hexString)
  {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hexString.length(); i += 2)
    {
      bytes.push_back(std::stoi(hexString.substr(i, 2), nullptr, 16));
    }
    return bytes;
  }

  std::vector<uint8_t> deriveKey(const std::string &masterPassword, const std::string &salt)
  {
    const int iterationCount = 10000;
    const int keyLength = 32;

    std::vector<uint8_t> derivedKey(keyLength);

    PKCS5_PBKDF2_HMAC(
        masterPassword.c_str(),
        masterPassword.length(),
        reinterpret_cast<const uint8_t *>(salt.c_str()),
        salt.length(),
        iterationCount,
        EVP_sha256(),
        keyLength,
        derivedKey.data());

    return derivedKey;
  }

  std::vector<uint8_t> encryptPassword(const std::string &password, const std::vector<uint8_t> &key)
  {
    const int ivSize = 12;
    const int tagSize = 16;

    std::vector<uint8_t> iv(ivSize);
    RAND_bytes(iv.data(), iv.size());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data());

    int ciphertextSize = password.length() + EVP_CIPHER_CTX_block_size(ctx);
    std::vector<uint8_t> ciphertext(ciphertextSize);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const uint8_t *>(password.c_str()), password.length());
    ciphertextSize = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertextSize += len;

    std::vector<uint8_t> tag(tagSize);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data());

    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> encryptedPassword(iv);
    encryptedPassword.insert(encryptedPassword.end(), ciphertext.begin(), ciphertext.begin() + ciphertextSize);
    encryptedPassword.insert(encryptedPassword.end(), tag.begin(), tag.end());

    return encryptedPassword;
  }

  std::string decryptPassword(const std::vector<uint8_t> &encryptedPassword, const std::vector<uint8_t> &key)
  {
    const int ivSize = 12;
    const int tagSize = 16;

    std::vector<uint8_t> iv(encryptedPassword.begin(), encryptedPassword.begin() + ivSize);
    std::vector<uint8_t> ciphertext(encryptedPassword.begin() + ivSize, encryptedPassword.end() - tagSize);
    std::vector<uint8_t> tag(encryptedPassword.end() - tagSize, encryptedPassword.end());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());

    int plaintextSize = ciphertext.size() + EVP_CIPHER_CTX_block_size(ctx);
    std::vector<uint8_t> plaintext(plaintextSize);

    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintextSize = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
      plaintextSize += len;
      return std::string(reinterpret_cast<char *>(plaintext.data()), plaintextSize);
    }
    else
    {
      return "";
    }
  }

  bool stringContainsSubstringIgnoreCase(const std::string &str, const std::string &sub)
  {
    std::string strCopy = str;
    std::transform(strCopy.begin(), strCopy.end(), strCopy.begin(), ::tolower);
    std::string subCopy = sub;
    std::transform(subCopy.begin(), subCopy.end(), subCopy.begin(), ::tolower);

    return strCopy.find(subCopy) != std::string::npos;
  }

  std::string generatePassword(int length)
  {
    if (length < 3)
    {
      throw std::runtime_error("Invalid password length. It must be at least of length 3. We recommend a length of 12 or more.");
    }

    std::string password = "";
    std::string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string numbers = "0123456789";
    std::string specialCharacters = "!@#$%^&*()_+{}[]:;\"'<>?,./|\\";
    std::string allCharacters = letters + numbers + specialCharacters;

    std::random_device rd;
    std::mt19937 generator(rd());

    std::uniform_int_distribution<int> lettersDistribution(0, letters.length() - 1);
    std::uniform_int_distribution<int> numbersDistribution(0, numbers.length() - 1);
    std::uniform_int_distribution<int> specialCharactersDistribution(0, specialCharacters.length() - 1);
    std::uniform_int_distribution<int> allCharactersDistribution(0, allCharacters.length() - 1);

    password += letters[lettersDistribution(generator)];
    password += numbers[numbersDistribution(generator)];
    password += specialCharacters[specialCharactersDistribution(generator)];

    for (int i = 0; i < length - 3; i++)
    {
      password += allCharacters[allCharactersDistribution(generator)];
    }

    std::shuffle(password.begin(), password.end(), generator);

    return password;
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
  std::string salt;

public:
  friend LoginInfoManager;
  LoginInfo(const std::string &id, const std::string &website, const std::string &username, const std::string &password, const std::string &userId, const std::string &salt) : id(id), website(website), username(username), password(password), userId(userId), salt(salt) {}

  LoginInfo(std::string website, std::string username, std::string password, std::string userId)
  {
    this->id = Utility::generateSimpleId();
    this->website = website;
    this->username = username;
    this->userId = userId;
    this->salt = Utility::generateSalt(SALT_SIZE);

    std::vector<uint8_t> key = Utility::deriveKey(currentMasterPassword, this->salt);
    std::vector<uint8_t> encryptedPassword = Utility::encryptPassword(password, key);

    this->password = Utility::bytesToHexString(encryptedPassword);
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

  std::string getSalt() const
  {
    return this->salt;
  }

  void updatePassword(const std::string &newPassword)
  {
    std::vector<uint8_t> key = Utility::deriveKey(currentMasterPassword, this->salt);
    std::vector<uint8_t> encryptedPassword = Utility::encryptPassword(newPassword, key);

    this->password = Utility::bytesToHexString(encryptedPassword);
  }

  void updateUsername(const std::string &newUsername)
  {
    this->username = newUsername;
  }

  void updateWebsite(const std::string &newWebsite)
  {
    this->website = newWebsite;
  }
};

class LoginInfoManager
{
  std::string filename;
  std::vector<std::shared_ptr<LoginInfo>> loginInfos;

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
      std::string id, website, username, password, userId, salt;

      std::getline(iss, id, ',');
      std::getline(iss, website, ',');
      std::getline(iss, username, ',');
      std::getline(iss, password, ',');
      std::getline(iss, userId, ',');
      std::getline(iss, salt, ',');

      this->loginInfos.push_back(std::make_shared<LoginInfo>(id, website, username, password, userId, salt));
    }
  }

  void addLoginInfo(const LoginInfo &loginInfo)
  {
    this->loginInfos.push_back(std::make_shared<LoginInfo>(loginInfo));
  }

  void saveLoginInfos() const
  {
    std::ofstream file(this->filename);

    if (!file.is_open())
    {
      throw CustomException("Error opening file.");
    }

    for (const auto &loginInfoPtr : this->loginInfos)
    {
      const LoginInfo &loginInfo = *loginInfoPtr;
      file << loginInfo.getId() << "," << loginInfo.getWebsite() << "," << loginInfo.getUsername() << ","
           << loginInfo.getPassword() << "," << loginInfo.getUserId() << "," << loginInfo.getSalt() << "\n";
    }

    file.close();
  }

  std::vector<LoginInfo> searchLoginInfos(const std::string &website, const std::string &userId) const
  {
    std::vector<LoginInfo> result;

    for (const auto &loginInfoPtr : this->loginInfos)
    {
      const LoginInfo &loginInfo = *loginInfoPtr;
      if (Utility::stringContainsSubstringIgnoreCase(loginInfo.getWebsite(), website) && loginInfo.getUserId() == userId)
      {
        result.push_back(loginInfo);
      }
    }

    return result;
  }

  std::vector<LoginInfo> getAllSavedWebsite(const std::string &userId) const
  {
    std::vector<LoginInfo> result;

    for (const auto &loginInfoPtr : this->loginInfos)
    {
      const LoginInfo &loginInfo = *loginInfoPtr;
      if (loginInfo.getUserId() == userId)
      {
        result.push_back(loginInfo);
      }
    }

    return result;
  }

  const std::shared_ptr<LoginInfo> getLoginInfo(const std::string &id) const
  {
    for (const auto &loginInfo : this->loginInfos)
    {
      if (loginInfo->getId() == id)
      {
        return loginInfo;
      }
    }

    throw CustomException("Login info not found.");
  }

  void deleteLoginInfo(const std::string &id)
  {
    for (const auto &loginInfo : this->loginInfos)
    {
      if (loginInfo->getId() == id)
      {
        this->loginInfos.erase(std::remove(this->loginInfos.begin(), this->loginInfos.end(), loginInfo), this->loginInfos.end());
        return;
      }
    }

    throw CustomException("Login info not found.");
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
    printText("4) Update Website");
    printText("5) Update Username");
    printText("6) Update Password");
    printText("7) Delete Login");
    printText("8) Generate Password");
    printText("9) Exit");
  }

  void printBorderedTableAllLoginHeader()
  {
    std::cout << "+------------------+------------------+------------------+------------------+\n";
    std::cout << "| ID               | Website          | Username         | Password         |\n";
    std::cout << "+------------------+------------------+------------------+------------------+\n";
  }

  void printBorderedTableAllLoginFooter()
  {
    std::cout << "+------------------+------------------+------------------+------------------+\n\n";
  }

  void printBorderedTableAllLogin(const LoginInfo &loginInfo)
  {
    std::string decryptedPassword = Utility::decryptPassword(Utility::hexStringToBytes(loginInfo.getPassword()), Utility::deriveKey(currentMasterPassword, loginInfo.getSalt()));

    std::cout << "| " << std::setw(16) << loginInfo.getId() << " | "
              << std::setw(16) << loginInfo.getWebsite() << " | "
              << std::setw(16) << loginInfo.getUsername() << " | " << std::setw(16) << decryptedPassword << " |\n";
  }

  void printBorderedTableSearchedLoginHeader()
  {
    std::cout << "+------------------+------------------+------------------+------------------+\n";
    std::cout << "| ID               | Website          | Username         | Password         |\n";
    std::cout << "+------------------+------------------+------------------+------------------+\n";
  }

  void printBorderedTableSearchedLoginFooter()
  {
    std::cout << "+------------------+------------------+------------------+------------------+\n\n";
  }

  void printBorderedTableSearchedLogin(const LoginInfo &loginInfo)
  {
    std::string decryptedPassword = Utility::decryptPassword(Utility::hexStringToBytes(loginInfo.getPassword()), Utility::deriveKey(currentMasterPassword, loginInfo.getSalt()));

    std::cout << "| " << std::setw(16) << loginInfo.getId() << " | "
              << std::setw(16) << loginInfo.getWebsite() << " | "
              << std::setw(16) << loginInfo.getUsername() << " | "
              << std::setw(16) << decryptedPassword << " |\n";
  }

  void askChoice()
  {
    do
    {
      printText("Enter your choice: ", false);
      std::cin >> this->choice;

      if (std::cin.fail() || choice < 1 || choice > 9)
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
        std::vector<LoginInfo> loginInfos = loginInfoManager.searchLoginInfos(this->website, currentUserId);

        if (loginInfos.empty())
        {
          printText("No logins found.");
        }
        else
        {
          printText("Logins found: \n");
          printBorderedTableSearchedLoginHeader();
          for (const LoginInfo &loginInfo : loginInfos)
          {
            printBorderedTableSearchedLogin(loginInfo);
          }
        }
        printBorderedTableSearchedLoginFooter();
        this->run();
      }
      else if (this->choice == 2)
      {
        LoginInfoManager loginInfoManager("loginInfos.csv");
        std::vector<LoginInfo> loginInfos = loginInfoManager.getAllSavedWebsite(currentUserId);

        if (loginInfos.empty())
        {
          printText("No logins found.");
        }
        else
        {
          printText("Existing Logins:\n");
          printBorderedTableAllLoginHeader();
          for (const LoginInfo &loginInfo : loginInfos)
          {
            printBorderedTableAllLogin(loginInfo);
          }
          printBorderedTableAllLoginFooter();
        }

        this->run();
      }
      else if (this->choice == 1)
      {
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
        printText("Enter Login info ID: ", false);
        std::string id, website;
        std::cin >> id;

        LoginInfoManager loginInfoManager("loginInfos.csv");
        const std::shared_ptr<LoginInfo> &loginInfoPtr = loginInfoManager.getLoginInfo(id);

        printText("Enter new website: ", false);
        std::cin >> website;

        loginInfoPtr->updateWebsite(website);
        loginInfoManager.saveLoginInfos();
        printText("Website updated successfully.");
        this->run();
      }
      else if (this->choice == 5)
      {
        printText("Enter Login info ID: ", false);
        std::string id, username;
        std::cin >> id;

        LoginInfoManager loginInfoManager("loginInfos.csv");
        const std::shared_ptr<LoginInfo> &loginInfoPtr = loginInfoManager.getLoginInfo(id);

        printText("Enter new username: ", false);
        std::cin >> username;

        loginInfoPtr->updateUsername(username);
        loginInfoManager.saveLoginInfos();
        printText("Username updated successfully.");
        this->run();
      }
      else if (this->choice == 6)
      {
        printText("Enter Login info ID: ", false);
        std::string id, password;
        std::cin >> id;

        LoginInfoManager loginInfoManager("loginInfos.csv");
        const std::shared_ptr<LoginInfo> &loginInfoPtr = loginInfoManager.getLoginInfo(id);

        printText("Enter new password: ", false);
        std::cin >> password;

        loginInfoPtr->updatePassword(password);
        loginInfoManager.saveLoginInfos();
        printText("Password updated successfully.");
        this->run();
      }
      else if (this->choice == 7)
      {
        printText("Enter Login info ID: ", false);
        std::string id;
        std::cin >> id;

        LoginInfoManager loginInfoManager("loginInfos.csv");
        loginInfoManager.deleteLoginInfo(id);
        loginInfoManager.saveLoginInfos();
        printText("Login deleted successfully.");
        this->run();
      }
      else if (this->choice == 8)
      {
        printText("Enter length of password: ", false);
        int length;
        std::cin >> length;
        Utility::clearInputBuffer();

        printText("Generated password: " + Utility::generatePassword(length));
        this->run();
      }
      else if (this->choice == 9)
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
        currentMasterPassword = user.getPassword();
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