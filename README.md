# Encryption & Decryption Tool

This project is a graphical user interface (GUI) application for encrypting and decrypting messages using the DES (Data Encryption Standard) algorithm. It is implemented in Python using the Tkinter library for the GUI.

## Features

- **GUI for Encryption and Decryption:** Provides a user-friendly interface for encrypting and decrypting messages.
- **DES Encryption Algorithm:** Utilizes the DES algorithm in CBC (Cipher Block Chaining) mode for secure encryption.
- **Hexadecimal Encoding:** Encrypts the message to a hexadecimal string and decodes it during decryption.
- **Input Validation:** Ensures that only valid hexadecimal input is used for decryption.
- **Clear Function:** Allows users to clear both input and output text areas.

## Code Overview
- **isHexadecimal(text): Checks if the provided text is a valid hexadecimal string.
- **encrypt(): Encrypts the input plaintext message using DES and displays the result in hexadecimal format.
- **decrypt(): Decrypts the input hexadecimal ciphertext back to plaintext and displays the result.
- **clear_text(): Clears the input and output text areas.
