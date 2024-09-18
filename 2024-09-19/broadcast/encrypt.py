import sys
from Crypto.Util.number import getStrongPrime
from Crypto.Random import get_random_bytes
import math

def pad(m: int, max: int) -> int:
    """
    Don't worry too much about what this function does.
    This function adds randomized padding to the plaintext m.
    
    Implementation explanation:

    mp = m * 256^k + bp
    where mp is the padded message, k is the number of padding bytes, and bp are the padding bytes.
    mp < (m + 1) * 256^k
    
    To find max padding bytes:
    (m + 1) * 256^k < max
    k < log_256(max / (m + 1))
    """

    num_padding_bytes = int(math.log(max, 256) - math.log(m + 1, 256))
    padding_bytes = get_random_bytes(num_padding_bytes - 1) # -1 for null byte after message
    padding = int.from_bytes(padding_bytes)
    m_pad = m * 256**num_padding_bytes + padding
    return m_pad

flag = sys.argv[1] # This is crypto, not pwn
flag = flag.encode()

e = 3

p1 = getStrongPrime(2048)
q1 = getStrongPrime(2048)
p2 = getStrongPrime(2048)
q2 = getStrongPrime(2048)
p3 = getStrongPrime(2048)
q3 = getStrongPrime(2048)

n1 = p1 * q1
n2 = p2 * q2
n3 = p3 * q3
n_min = min([n1, n2, n3])

m = int.from_bytes(flag)
m = pad(m, n_min)

c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)

print(f"e = {e}")
print(f"n1 = {n1}")
print(f"n2 = {n2}")
print(f"n3 = {n3}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")
print(f"c3 = {c3}")
