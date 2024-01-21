from Crypto.Cipher import ARC4


with open('lol.bin', 'rb') as f:
	lol = f.read()
print(lol.hex())

rc4_key = b'daidaidaidaidaisuki'

rc4 = ARC4.new(rc4_key)
lol_rc4 = rc4.decrypt(lol)

print(lol_rc4.hex())

print(list(map(int, lol_rc4)))

