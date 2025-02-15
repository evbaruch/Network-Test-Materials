import math

def gcd(a, b):
    """Compute the greatest common divisor (GCD) using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Compute modular inverse of e modulo phi using Extended Euclidean Algorithm."""
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi
    while e > 0:
        temp1, temp2 = divmod(temp_phi, e)
        x, y = x2 - temp1 * x1, d - temp1 * y1
        temp_phi, e, x2, x1, d, y1 = e, temp2, x1, x, y1, y
    return d + phi if d < 0 else d

# Step 1: Choose two prime numbers
P = 17
Q = 23

# Step 2: Compute N (the modulus)
N = P * Q  # 17 * 23 = 391

# Step 3: Compute Totient (T = (P-1)*(Q-1))
T = (P - 1) * (Q - 1)  # (17-1)*(23-1) = 352

# Step 4: Choose public exponent E (must be prime and 1 < E < T, gcd(E, T) = 1) 
E = 113  # Given in the slide

# Step 5: Compute private key D (D is the modular inverse of E mod T) -> D * E mod T = 1
D = mod_inverse(E, T)  # Should return 81

# Step 6: Encryption function
def encrypt(plain_text, E, N):
    """Encrypt a message using RSA encryption."""
    cipher_text = [pow(ord(char), E, N) for char in plain_text]
    return cipher_text

# Step 7: Decryption function
def decrypt(cipher_text, D, N):
    """Decrypt a message using RSA decryption."""
    plain_text = ''.join(chr(pow(char, D, N)) for char in cipher_text)
    return plain_text

# Example usage
# The sender knows the public key (E,N) and uses it to encrypt messages.
message = "HELLO"
cipher = encrypt(message, E, N)

# The receiver knows the private key D and uses it to decrypt messages.
decrypted_message = decrypt(cipher, D, N)
# Anyone intercepting the encrypted message (ciphertext)
# would need to factor N into P and Q to compute T and D,
# which is difficult due to the computational complexity.


# Display results
print("Original Message:", message)
print("Encrypted Message:", cipher)
print("Decrypted Message:", decrypted_message)
