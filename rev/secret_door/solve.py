
first = 78
last = 33

with open('encoded.bin', 'rb') as f:
	enc = f.read()

data = []
for i in range(90245 + 1):
	if i % 2:
		data.append(enc[i] ^ last)
	else:
		data.append(enc[i] ^ first)

data = bytes(data)
with open('door.jpg', 'wb') as f:
	f.write(data)
