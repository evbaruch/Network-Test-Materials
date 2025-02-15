import random

# P G Explanation:
# In the Diffie-Hellman key exchange, the values of P (a prime number) and G (a generator, or primitive root modulo P) are publicly agreed upon.
#
# 1. Choosing P (a Prime Number):
#    - P should be a large prime number to ensure security.
#    - It is publicly shared and should be a safe prime (meaning (P-1)/2 is also prime) for better security.
#
# 2. Choosing G (Generator or Primitive Root modulo P):
#    - G is a primitive root modulo P, meaning that it generates all numbers from 1 to P-1 when exponentiated.
#    - For a given prime P, G must satisfy:
#      - G^k mod P produces all values from 1 to P-1 (where k runs from 1 to P-1).
#    - Typically, small values like 2, 3, 5 are used and tested for primitiveness.
#
# For real-world cryptographic applications, much larger prime numbers (e.g., 2048-bit primes) are used to prevent attacks.

# Step 1: Agree on public parameters (Prime number and Generator)
P = 23  # A prime number (publicly shared)
G = 5   # A primitive root modulo P (publicly shared)

# Step 2: Alice and Bob each choose private keys
alice_private = random.randint(2, P-2)  # Alice's private key (kept secret)
bob_private = random.randint(2, P-2)    # Bob's private key (kept secret)

# Step 3: Compute public keys
alice_public = pow(G, alice_private, P)  # Alice computes public key
bob_public = pow(G, bob_private, P)      # Bob computes public key

# Step 4: Exchange public keys (these are shared over an insecure channel)

# Step 5: Compute shared secret
alice_shared_secret = pow(bob_public, alice_private, P)
bob_shared_secret = pow(alice_public, bob_private, P)

# Step 6: Both secrets should be the same
assert alice_shared_secret == bob_shared_secret

# Display results
print("Public Prime (P):", P)
print("Public Base (G):", G)
print("Alice's Private Key:", alice_private)
print("Bob's Private Key:", bob_private)
print("Alice's Public Key:", alice_public)
print("Bob's Public Key:", bob_public)
print("Shared Secret (computed by Alice):", alice_shared_secret)
print("Shared Secret (computed by Bob):", bob_shared_secret)
