## Sanduk

### Overview

This is a simple Command Line Interface (CLI) based password manager built in C++. It allows users to securely store and retrieve passwords for various accounts in a local database.

### Features

- **Secure Storage**: Passwords are encrypted and stored securely in the local database.
- **User-Friendly Interface**: Easy-to-use command line interface for managing passwords.
- **Password Generation**: Option to generate strong and random passwords.
- **Master Password**: Access to the password manager requires a master password for added security.

### Prerequisites

- C++ compiler (e.g., g++)
- Make utility

### How to Run

1. Clone the repository to your local machine:

    ```bash
    git clone <repository-url>
    ```

2. Navigate to the project directory:

    ```bash
    cd <project-directory>
    ```

3. Build the password manager using the provided Makefile:

    ```bash
    make main
    ```

4. Run the password manager:

    ```bash
    ./main
    ```

### Usage

- Upon running the password manager, you will be prompted to enter your master password. If it's your first time running the program, it will guide you to set up a master password.

- Use the menu options to perform various operations, such as adding a new password, retrieving a password, updating a password, or generating a new password.

- Follow the on-screen instructions for each operation.
