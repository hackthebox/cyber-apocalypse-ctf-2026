import hashlib, itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

q = 2
N = 137

K = GF(q)
_vars = [f"x{i}" for i in range(1, N+1)]
R = PolynomialRing(K, _vars, N)

VARS = R.gens()
x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58, x59, x60, x61, x62, x63, x64, x65, x66, x67, x68, x69, x70, x71, x72, x73, x74, x75, x76, x77, x78, x79, x80, x81, x82, x83, x84, x85, x86, x87, x88, x89, x90, x91, x92, x93, x94, x95, x96, x97, x98, x99, x100, x101, x102, x103, x104, x105, x106, x107, x108, x109, x110, x111, x112, x113, x114, x115, x116, x117, x118, x119, x120, x121, x122, x123, x124, x125, x126, x127, x128, x129, x130, x131, x132, x133, x134, x135, x136, x137 = VARS
# x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32 = R.gens()

PRK.<x> = PolynomialRing(K)
x = PRK.gen()

def eval_gb(gb, vars_, vals):
    subs = {var_: vals[i] for i,var_ in enumerate(vars_)}
    eqs = [f.subs(subs) for f in gb]
    return eqs

def fetch_solutions(gb):
    evaled_equations = []
    quadratic_vars = []
    for offset, f in enumerate(gb):
        if f.degree() == 2:
            quadratic_vars.append(f.variable())

    for vals in itertools.product([0,1], repeat=len(quadratic_vars)):
        subs = dict(zip(quadratic_vars, vals))
        evaled_equation = eval_gb(gb, quadratic_vars, vals)
        soln_bits = [0 for _ in range(len(evaled_equation))]
        for i, eqtn in enumerate(evaled_equation):
            mons = R(eqtn).monomials()
            if len(mons) == 0:
                soln_bits[i] = subs[VARS[i]]
            else:
                soln_bits[i] = int(len(eqtn.coefficients()) % 2 == 0)
        yield "".join(map(str, soln_bits))

def degree_reduction(sys_equations):
    for removedItem in ["^2", "^3", "^4"]:
        sys_equations = sys_equations.replace(removedItem, "") 
    return sys_equations

# thanks to
# https://github.com/falay/The-Attack-on-Hidden-Field-Equations-with-Improved-Grobner-Basis-Approach/blob/master/HFE.sage
def recover_plaintexts_grobner(PK, ciphertext):
    n = len(PK)

    equations = ""
    variables = ""
    for i in range(n):
        variables += f"x{i+1},"
        equations += f"{PK[i]}-{ciphertext[i]},"

    equations = equations[:-1]
    variables = variables[:-1]

    Pring = PolynomialRing(GF(q), variables, order="lex")
    Pring.inject_variables(verbose=False)

    # Optimization

    equations = degree_reduction(equations)
    I = Ideal(sage_eval(equations, locals=Pring.gens_dict()))
    J = I + sage.rings.ideal.FieldIdeal(Pring)
    # return fetch_solutions(J.variety())
    gb = list(J.groebner_basis(algorithm='singular:std'))
    return fetch_solutions(gb)

PK, encrypted_key, enc_flag = open("output.txt").readlines()
PK, encrypted_key, enc_flag = eval(PK.strip().replace("^", "**")), eval(encrypted_key.strip()), bytes.fromhex(enc_flag.strip())

for recovered_pt in recover_plaintexts_grobner(PK, encrypted_key):
    KEY_candidate = int(recovered_pt[::-1], 2)
    AES_KEY = hashlib.sha256(str(KEY_candidate).encode()).digest()
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        print(f"KEY CANDIDATE: {AES_KEY.hex()}")
        print(unpad(cipher.decrypt(enc_flag), 16))
    except:
        pass