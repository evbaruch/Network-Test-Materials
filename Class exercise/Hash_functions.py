import hashlib

# Explanation of Hash Functions:

# MD5 (Message Digest Algorithm 5)
# - Produces a 128-bit (16-byte) hash value, typically represented as a 32-character hexadecimal number.
# - It was widely used for checksums and data integrity but is now considered cryptographically broken due to collision vulnerabilities.
# - Faster but insecure for cryptographic applications.

# SHA-1 (Secure Hash Algorithm 1)
# - Produces a 160-bit (20-byte) hash value, typically represented as a 40-character hexadecimal number.
# - Stronger than MD5 but still considered weak due to collision attacks.
# - Previously used for SSL/TLS certificates, but now deprecated.

# SHA-256 (Secure Hash Algorithm 2 - 256-bit)
# - Part of the SHA-2 family, produces a 256-bit (32-byte) hash value, represented as a 64-character hexadecimal number.
# - Much more secure than MD5 and SHA-1.
# - Used in digital signatures, blockchain, and password hashing.

# Initializing strings
str1hash = "Hello cool cyber class"
str2hash = "Hello cool cyber class."

# Encoding strings
encoded_str1 = str1hash.encode()
encoded_str2 = str2hash.encode()

# MD5 Hash (128-bit, 32-character hex)
md5_hash1 = hashlib.md5(encoded_str1).hexdigest()
md5_hash2 = hashlib.md5(encoded_str2).hexdigest()

# SHA-1 Hash (160-bit, 40-character hex)
sha1_hash1 = hashlib.sha1(encoded_str1).hexdigest()
sha1_hash2 = hashlib.sha1(encoded_str2).hexdigest()

# SHA-256 Hash (256-bit, 64-character hex)
sha256_hash1 = hashlib.sha256(encoded_str1).hexdigest()
sha256_hash2 = hashlib.sha256(encoded_str2).hexdigest()

# Printing the results
print("MD5 Hashes:")
print("String 1:", md5_hash1)
print("String 2:", md5_hash2)

print("\nSHA-1 Hashes:")
print("String 1:", sha1_hash1)
print("String 2:", sha1_hash2)

print("\nSHA-256 Hashes:")
print("String 1:", sha256_hash1)
print("String 2:", sha256_hash2)
