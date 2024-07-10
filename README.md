**In this repo you will find the python scripts I have created to aid me in my journey of reverse engineering Malware in Ghidra.
**
**VidarDecrypt.py** - This python script is intended for use within the Ghidra Script Manager. When pointed to the function which passes the encrypted strings to the decryption function, this script will decrypt the strings, and rename the variables (they are subsequently stored in) using the decrypted value. The aim of this script is to make it easier to see what API calls and strings are being used during static analysis/reverse engineering Vidar Stealer.
