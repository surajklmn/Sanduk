#include <iostream>
class UserInterface
{
  static const int MAX_WIDTH = 50;
  static const char DEFAULT_LINE_CHAR = '*';

public:
  void printLine(char c = DEFAULT_LINE_CHAR)
  {
    for (int i = 0; i < MAX_WIDTH; i++)
    {
      std::cout << c;
    }
    std::cout << '\n';
  }

  void printCenteredText(const std::string &text)
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

  void printText(const std::string &text, bool newLine = true)
  {
    std::cout << text << (newLine ? '\n' : ' ');
  }

void printWelcomeScreen()
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

  void printCreateUserScreen()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Create User");
    printLine(DEFAULT_LINE_CHAR);
  }

  void printLoginScreen()
  {
    printLine(DEFAULT_LINE_CHAR);
    printCenteredText("Login");
    printLine(DEFAULT_LINE_CHAR);
  }
};