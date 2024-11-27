XOR, ROTATION, ADDICTION, NOT, SHA3-256 사용
블록크기 : 128bit 키크기 : 256bit 라운드횟수 : 32

암호화 키 앞부분 128bit : key[0] 뒷부분 128bit : key[1] 으로 나누어 사용

data[i] = data[i] + data[i+1] // 0->N
data[N] = data[N] + key[0]

data[i] = data[i] ^ key[1]

data[i] = rotate_r(data[i], i)

data[i] = data[i] + data[i-1] // N->0
data[0] = data[0] + key[0]

data[i] = !data[i]

key = sha3_256(key)

암호화 위 과정 32번 반복

복호화는 거꾸로
