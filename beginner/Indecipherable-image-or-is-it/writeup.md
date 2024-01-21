binwalk -e cutie.png
cutie.png on aperisolve gives: keka{1b0asx2w_hbin9K_Ah_6xwm0L}

cd _cutie.png.extracted/SECRET
images.jpeg on aperisolve gives: easyone

steghide extract -sf images.jpeg
password: easyone

in a.txt get: F4K5FL4G

vigenere with numbers in alphabet (ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890)
text: keka{1b0asx2w_hbin9K_Ah_6xwm0L}
key: F4K5FL4G

flag{v1g5n5r3_c1ph4R_1n_1m4g5S}
