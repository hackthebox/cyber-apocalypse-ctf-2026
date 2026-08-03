from sage.all import *

n = 0x8cae7d6a15e55fb6bea05fa3b7989cba4a4678d5d78103b80f78cf78b68602ea499ba6baf4f9d609fd16dd00e19823f12d8592af50b80efc4fdb7525bcff0b71fbbec3fa084b48c31e47e7bfe9b5424bbf8a2f707a1cbf89136e51e687f3c2b8000d1716f2686a4e48d08822e64b0ffc2b3218c4496d47bcf7c78b66360e600a00dbe7e22e38df603047962c97aef6b9e56f4eda27b648d67643ce7d9006f42108ff0cadcbb801eab6e13b1d59b6283c9d5348e388c173e6e870714e678d79c775945fac24da51604b2f1984f0f09b22ecbc849aa12fe883d4e7304d2f18a3cc684eda1cec71457d760da0a8e7aa0a7e2ce98bc1019078ed98a351dbf12095
e = 0x10001
q_upper = 0xc0b1b1709eff60282af463c34b5e9c1cf35912662b6d25fe6adcd40413b68cb620d106d77e2b532077d4fb9e43a88c4540e72ef826a1acf41044ea1900020f8342dd68677edd1dffae

bits_p = 1024
bits_upper = Integer(q_upper).nbits()
t = bits_p - bits_upper

for b in range(256):
    PR.<x> = PolynomialRing(Zmod((n<<8)+b))
    f = q_upper * (2^t) + x
    roots = f.small_roots(X=2^t, beta=0.5, epsilon=1/17)
    if roots:
        x0 = int(roots[0])
        q = int(q_upper) * (2**t) + x0
        n = (n<<8) + b
        if n % q == 0:
            p = n // q
            print(f'{p = }')
            print(f'{q = }')
            phi = (p - 1) * (q - 1)
            d = inverse_mod(e, phi)
            enc_flag = int.from_bytes(open('flag.enc', 'rb').read())
            m = int(pow(enc_flag, d, n))
            print(int.to_bytes(m, length=(m.bit_length()+7)//8, byteorder='big'))
            break