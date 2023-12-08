#include <iostream>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <vector>

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

int main()
{
  std::string password = "hello123";

  std::string salt = generateSalt(18);
  std::string hashedPassword = hashString(password, salt);

  std::cout << "Password: " << password << std::endl;
  std::cout << "Salt: " << salt << std::endl;
  std::cout << "Hashed password: " << hashedPassword << std::endl;
  std::cout << "=============================================================\n";
  std::cout << "TEST\n";
  std::cout << "Test hashed password: " << hashString(password, salt) << std::endl;

  if (hashedPassword == hashString(password, salt))
  {
    std::cout << "Password is correct\n";
  }
  else
  {
    std::cout << "Password is incorrect\n";
  }
}