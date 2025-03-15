# URUK

Understanding and Using the URUK File Encryption & Decryption Program

The URUK program is a lightweight, cross-platform application designed to securely encrypt and decrypt files using advanced cryptographic techniques. Built with Python and Tkinter, URUK offers a user-friendly graphical interface for encrypting files with AES and RSA algorithms, signing them for integrity, and decrypting them with signature verification. This article provides a summary of the program, instructions for running it on various operating systems (Windows, Linux, macOS), and a step-by-step guide on how to use its features.


Program Summary

URUK is a file encryption and decryption tool developed by Ali Al-Kazaly, also known as "aLiGeNiUs The Hackers." The program, version 1.0.0.0 (2025), focuses on providing secure file handling with the following key features:

    Password Protection:
        URUK uses a password-based authentication system to secure access to its features.
        Passwords are encrypted using the Fernet symmetric encryption algorithm (part of the cryptography library) and stored in a file (password.enc), with the encryption key saved in key.key.
        Users must set an initial password (minimum 8 characters) on first use and can change it later.
    File Encryption:
        Files are encrypted using AES (Advanced Encryption Standard) with user-selectable key lengths (128, 192, or 256 bits).
        The AES key is randomly generated and displayed in hexadecimal format for the user to save.
        Files are also signed using RSA (Rivest-Shamir-Adleman) with a 2048-bit key pair to ensure integrity.
        Public and private keys are generated during encryption and can be saved as .pem files.
        The encrypted file includes the initialization vector (IV), encrypted data, and RSA signature, saved with a .enc extension.
    File Decryption:
        Decryption requires the AES key, private key, and the original file (for signature verification).
        The program verifies the RSA signature to ensure the file hasn’t been tampered with before decrypting it.
        Decrypted files are saved with a .dec extension.
    User Interface:
        The main window is divided into two sections: Encryption (left) and Decryption (right), using a PanedWindow for resizable panels.
        An "About" button displays program information, including the app name, developer, and version.
        The window size dynamically adjusts to 80% of the screen width and 60% of the screen height, ensuring compatibility across different screen resolutions.
    Cross-Platform Compatibility:
        URUK is built with Python and Tkinter, making it compatible with Windows, Linux, and macOS.
        It uses the cryptography library for encryption, which works consistently across all operating systems.
        File paths are handled using os.path, ensuring proper path separators (\ for Windows, / for Linux/macOS).

The program has been simplified by removing a previous "Folder Compression Section" to eliminate dependencies on external libraries like pyminizip, which caused compatibility issues. Now, URUK focuses solely on encryption and decryption, making it more reliable and easier to use across all platforms.


How to Run URUK on All Operating Systems

URUK can be run on Windows, Linux, and macOS either directly with Python or as a standalone executable created with PyInstaller. Below are the steps to set up and run the program on each OS.
Prerequisites

    Python: Python 3.6 or higher.
    Dependencies: The cryptography library (Tkinter is included with Python).

Step 1: Install Python and Dependencies

    Windows:
        Download and install Python from python.org. During installation, check "Add Python to PATH."
        Open Command Prompt and install the required library:
        bash

        pip install cryptography

    Linux (e.g., Ubuntu):
        Install Python and pip:
        bash

        sudo apt update
        sudo apt install python3 python3-pip

        Install cryptography:
        bash

        pip3 install cryptography

        Ensure Tkinter is installed:
        bash

        sudo apt install python3-tk

    macOS:
        Install Python using Homebrew (if not already installed):
        bash

        brew install python3

        Install cryptography:
        bash

        pip3 install cryptography

        Tkinter is included with Python on macOS.

Step 2: Save the Code

    Copy the provided code into a file named URUK.py and save it in a directory of your choice.

Step 3: Run the Program Directly (For Development)

    Windows/Linux/macOS:
        Open a terminal or Command Prompt in the directory containing URUK.py.
        Run the program:
        bash

        python3 URUK.py

            On Windows, you may use python URUK.py if python3 is not recognized.
        The program will launch, prompting you to set an initial password if it’s the first run.

Step 4: Create a Standalone Executable (For Easy Use)
To run URUK without requiring Python on the target system, you can convert it to a standalone executable using PyInstaller.

    Install PyInstaller:
    bash

    pip install pyinstaller

    Windows (Create .exe):
        Open Command Prompt in the directory containing URUK.py.
        Run:
        bash

        pyinstaller --onefile --noconsole URUK.py

            --onefile: Creates a single executable file.
            --noconsole: Hides the console window (since it’s a GUI app).
        Find the executable in the dist folder (dist/URUK.exe).
        Double-click URUK.exe to run. You may need to allow it through Windows Defender (it might flag it as an unknown app).
    Linux (Create Binary):
        Open a terminal in the directory containing URUK.py.
        Run:
        bash

        pyinstaller --onefile URUK.py

        Find the binary in the dist folder (dist/URUK).
        Make it executable and run:
        bash

        chmod +x dist/URUK
        ./dist/URUK

    macOS (Create Binary):
        Open a terminal in the directory containing URUK.py.
        Run:
        bash

        pyinstaller --onefile URUK.py

        Find the binary in the dist folder (dist/URUK).
        Make it executable and run:
        bash

        chmod +x dist/URUK
        ./dist/URUK

        You may need to allow the app in "Security & Privacy" settings (macOS Gatekeeper might block it initially).



Notes on Executables

    The executable bundles all dependencies (tkinter, cryptography), so Python doesn’t need to be installed on the target system.
    The program is lightweight and should run smoothly on any modern system.

How to Use URUK
URUK provides a straightforward interface for encrypting and decrypting files securely. Below are the steps to use its features:
1. Initial Setup and Login

    First Run:
        Launch the program (python3 URUK.py or the executable).
        A "Set Initial Password" window will appear.
        Enter a password (minimum 8 characters) and click "Set Password."
    Subsequent Runs:
        The "Login" window will appear.
        Enter your password and click "Login."
        To change the password, enter the current password, click "Change Password," and follow the prompts to set a new password (must match confirmation and be at least 8 characters).

2. Main Application Interface

    After logging in, the main window opens with two sections:
        Encryption Section (left): For encrypting files.
        Decryption Section (right): For decrypting files.
    An "About" button at the top displays program information.

3. Encrypting a File

    In the Encryption Section, click "Select File to Encrypt" to choose a file.
        The file name will appear below the button.
    Select an AES key length (128, 192, or 256 bits) from the dropdown menu.
    Click "Encrypt & Sign File" to encrypt the file with AES and sign it with RSA.
        The public key, private key, and AES key will be displayed in the text boxes (copyable).
    Click "Save Public Key," "Save Private Key," and "Save AES Key" to save the keys as .pem and .key files, respectively.
        These keys are essential for decryption, so store them securely.
    Click "Save Encrypted File" to save the encrypted file (with a .enc extension).

4. Decrypting a File

    In the Decryption Section, click "Select File to Decrypt" to choose an encrypted .enc file.
        The file name will appear below the button.
    Click "Decrypt File."
    Select the private key (.pem) file when prompted.
    Select the AES key (.key) file when prompted.
    Select the original file used for encryption (needed for signature verification).
        If the signature verification fails, a warning will appear, but decryption will still proceed.
    Choose a save location for the decrypted file (with a .dec extension).
        A success message will confirm the file has been decrypted and saved.

5. Viewing Program Information

    Click the "About" button at the top to display program details:

    APP : URUK

    DEVELOPER : Ali Al-Kazaly aLiGeNiUs The Hackers

    VERSION : 1.0.0.0  (2025)

    The About dialog is a custom window centered on the main application, with an "OK" button to close it.



Additional Notes

    Security:
        URUK uses industry-standard encryption (AES, RSA) and symmetric key encryption (Fernet) for password storage.
        Always save the AES key, public key, and private key during encryption, as they are required for decryption.
        Keep the password.enc and key.key files secure, as they store the encrypted password and encryption key.
    Cross-Platform Compatibility:
        The program has been tested on Windows, Linux, and macOS and works consistently.
        File dialogs and path handling are OS-agnostic, ensuring a seamless experience.
    Troubleshooting:
        If the program fails to launch, ensure Python and the cryptography library are installed.
        On Linux, ensure python3-tk is installed if Tkinter is missing.
        If the executable is blocked, allow it through your OS’s security settings.

Conclusion
URUK is a powerful yet simple tool for securely encrypting and decrypting files, making it ideal for users who need to protect sensitive data. Its cross-platform compatibility, user-friendly interface, and robust cryptographic implementation make it a reliable choice for both beginners and advanced users. By following the setup instructions for your operating system and the usage guide, you can easily encrypt and decrypt files while ensuring their integrity through digital signatures. Whether you're on Windows, Linux, or macOS, URUK provides a consistent and secure experience for managing your files.
For further enhancements or support, the developer, Ali Al-Kazaly, continues to refine URUK, ensuring it meets user needs while maintaining simplicity and reliability. Happy encrypting! 😊

