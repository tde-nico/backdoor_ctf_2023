import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

c = bytes.fromhex('af95a58f4fbab33cd98f2bfcdcd19a101c04232ac6e8f7e9b705b942be9707b66ac0e62ed38f14046d1cd86b133ebda9')
nums = [600848253359, 617370603129, 506919465064, 218995773533, 831016169202, 501743312177, 15915022145, 902217876313, 16106924577, 339484425400, 372255158657, 612977795139, 755932592051, 188931588244, 266379866558, 661628157071, 428027838199, 929094803770, 917715204448, 103431741147, 549163664804, 398306592361, 442876575930, 641158284784, 492384131229, 524027495955, 232203211652, 213223394430, 322608432478, 721091079509, 518513918024, 397397503488, 62846154328, 725196249396, 443022485079, 547194537747, 348150826751, 522851553238, 421636467374, 12712949979]
s = 7929089016814

LEN = len(nums)

M = [[0] * (LEN + 1) for _ in range(LEN + 1)]
for i in range(LEN):
	M[i][i] = 2
	M[i][-1] = nums[i]
	M[-1][i] = 1
M[-1][-1] = s

M = Matrix(ZZ, M)

r = M.BKZ()
for i in r:
	if len(set(i[:-1])) == 2:
		F = i


secret = ''.join([
	str(i)
	for i in [
		0
		if i == 1
		else 1
		for i in F[:-1]
	]
][::-1])

assert sum([nums[i] for i in range(LEN) if secret[LEN-i-1] == '1']) == s

secret = long_to_bytes(int(secret, 2))

key = hashlib.sha256(secret).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(c)

print(flag)

# flag{N0t_r34dy_f0r_M3rkl3-H3llman}
