#include <iostream>

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

int main()
{
  printWelcomeScreen();
  return 0;
}