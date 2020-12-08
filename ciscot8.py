#Example
#password cisco is $8$Wf3elg36AU/wWE$k1EIeucQ0O356wFztLCA0JF8y4E6L5GXSC65r802Ivc

import hashlib

def _crypt_to64_wpa(v, n):
	itoa = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
	res = ''

	for i in range(n,0,-1):
		res += itoa[(v&0xFC0000)>>18:((v&0xFC0000)>>18)+1]
		v <<= 6

	return res


def base64_wpa(pwd):
	final = pwd
	ln = len(final)
	mod = ln%3
	cnt = round((ln-mod)/3)
	out = ''
	l = ''

	for i in range(0,cnt):
		mul = i*3
		l = (ord(final[mul:mul+1])<<16) | (ord(final[mul+1:mul+2])<<8) | (ord(final[mul+2:mul+3]))
		out += _crypt_to64_wpa(l, 4)

	mul = (i + 1)*3
	if mod == 2:
		l = (ord(final[mul:mul+1]) << 16) | (ord(final[mul+1:mul+2]) << 8)
		out += _crypt_to64_wpa(l, 3)
	if mod == 1:
		l = ord(final[mul:mul+1]) << 16
		out += _crypt_to64_wpa(l, 2)

	return out

if __name__ == '__main__':
	salt = input('Input salt: ')
	pwd = input('Input password: ')
	r = hashlib.pbkdf2_hmac('sha256', str.encode(pwd), str.encode(salt), 20000, dklen=32)

	print(f'$8${salt}${base64_wpa(r)}')