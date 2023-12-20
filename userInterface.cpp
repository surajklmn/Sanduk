#include <iostream>
class UserInterface
{
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

};

class WelcomeInterface{
  int choice;
  public:
  void displayHeading(){
    UserInterface::printLine();
    UserInterface::printCenteredText("Welcome to Sanduk");
    UserInterface::printLine();

  }
  void displayOptions(){
    UserInterface::printText("1:Create User");
    UserInterface::printText("2:Login");
    UserInterface::printText("3:Exit");

  }
  int setChoice(){
    UserInterface::printText("Enter you choice: ",false);
    std::cin >> choice;
  }
  bool isChoiceValid(){
    if(choice < 1 && choice >> 3){
      return false;
    }
  return true;
  }
  void setChoiceUntilValid(){
    do{
      setChoice();

      if(!isChoiceValid()){
      UserInterface::printText("Invalid Choice.");
      }
    }
    while(isChoiceValid());
  }

};
class LoginInterface{
  int choice;


};