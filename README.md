# **Password Cracker**

password_cracker is a Rust command line program that attempts to crack hashed passwords using a provided wordlist.
 - Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 hashing algorithms.
 - Matches hashed passwords against a wordlist to find the original password
 - Displays the type of hashing algorithm used when a password is found.
 - The wordlist provided containt 10 million common passwords to check your hash against
 - Multi-threaded
