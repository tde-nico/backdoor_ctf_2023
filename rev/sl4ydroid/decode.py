k1 = b"Yc^XtMfu"
n1 = b"0,S[)"
d1 = b"~?z?^S8o"
k21 = b"xP78V`m?3XeL"


for k in k1:
	print(chr((k + 8) ^ 7), end="")

N = len(n1)
for i in range(len(n1)):
	print('#', end='')

for i in range(len(d1)):
	print(chr(d1[i] ^ 0xC), end="")

for i in range(len(k21)):
	print('#', end='')


# rest of the flag dumped with cheat engine

# flag{RizZZ! Rc4_R3v3r51Ngg_RrR!:}
