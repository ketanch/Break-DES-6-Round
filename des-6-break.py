from itertools import product
from pwn import *
from os import urandom

#config
host = "##REDACTED##"
user = "##REDACTED##"
password = "##REDACTED##"
team_name = 'g1v3m3chee53'
team_pass = '##REDACTED##'
#Plaintext xor for the 2 different characterstics
pt_xor = (
    '4008000004000000',
    '0020000800000400'
)
key_dict = {}
partial_key = []
k6 = []
round_keys = ['$'] * 6
kf = 0

sbox =  [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],  
          [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],  
          [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],  
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]], 

         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],  
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],  
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],  
           [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]],  
    
         [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],  
           [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],  
           [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],  
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]],  
        
          [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],  
           [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],  
           [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],  
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ],  
         
          [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],  
           [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],  
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],  
           [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]],  
        
         [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],  
           [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],  
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],  
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ],  
          
          [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],  
           [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],  
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],  
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ],  
         
         [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],  
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],  
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],  
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] ]

exp = [32, 1, 2, 3, 4, 5,
      4, 5,6, 7, 8, 9,
      8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17, 
      16, 17, 18, 19, 20, 21, 
      20, 21, 22, 23, 24, 25, 
      24, 25, 26, 27, 28, 29,
      28, 29, 30, 31, 32, 1]

per = [16, 7, 20, 21, 
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31,10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25]

inv_p = [9, 17, 23, 31,
	13, 28, 2, 18,
	24, 16, 30, 6,
	26, 20, 10, 1,
	8, 14, 25, 3,
	4, 29, 11, 19,
	32, 12, 22, 7,
	5, 27, 15, 21]

ip = [58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7]

fp = [ 40, 8, 48, 16, 56, 24, 64, 32,  
    39, 7, 47, 15, 55, 23, 63, 31,  
    38, 6, 46, 14, 54, 22, 62, 30,  
    37, 5, 45, 13, 53, 21, 61, 29,  
    36, 4, 44, 12, 52, 20, 60, 28,  
    35, 3, 43, 11, 51, 19, 59, 27,  
    34, 2, 42, 10, 50, 18, 58, 26,  
    33, 1, 41, 9, 49, 17, 57, 25 ]

ifp = [8, 40, 16, 48, 24, 56, 32, 64,
       7, 39, 15, 47, 23, 55, 31, 63,
       6, 38, 14, 46, 22, 54, 30, 62,
       5, 37, 13, 45, 21, 53, 29, 61,
       4, 36, 12, 44, 20, 52, 28, 60,
       3, 35, 11, 43, 19, 51, 27, 59,
       2, 34, 10, 42, 18, 50, 26, 58,
       1, 33,  9, 41, 17, 49, 25, 57]

iip = [57, 49, 41, 33, 25, 17,  9, 1, 
       59, 51, 43, 35, 27, 19, 11, 3,
       61, 53, 45, 37, 29, 21, 13, 5,
       63, 55, 47, 39, 31, 23, 15, 7,
       58, 50, 42, 34, 26, 18, 10, 2,
       60, 52, 44, 36, 28, 20, 12, 4,
       62, 54, 46, 38, 30, 22, 14, 6,
       64, 56, 48, 40, 32, 24, 16, 8]

keyp = [57, 49, 41, 33, 25, 17, 9,  
        1, 58, 50, 42, 34, 26, 18,  
        10, 2, 59, 51, 43, 35, 27,  
        19, 11, 3, 60, 52, 44, 36,  
        63, 55, 47, 39, 31, 23, 15,  
        7, 62, 54, 46, 38, 30, 22,  
        14, 6, 61, 53, 45, 37, 29,  
        21, 13, 5, 28, 20, 12, 4 ]

shift_table = [1, 1, 2, 2,  
                2, 2, 2, 2,  
                1, 2, 2, 2,  
                2, 2, 2, 1 ] 

key_comp = [14, 17, 11, 24, 1, 5,  
            3, 28, 15, 6, 21, 10,  
            23, 19, 12, 4, 26, 8,  
            16, 7, 27, 20, 13, 2,  
            41, 52, 31, 37, 47, 55,  
            30, 40, 51, 45, 33, 48,  
            44, 49, 39, 56, 34, 53,  
            46, 42, 50, 36, 29, 32 ]

k6tk = [16, 9, 0, 42, 43, 40, '$', '$', '$', 5, 22, 33, 24, 34, 41, '$', 3, 15, 14, 36, 31, 47, 25, '$', 12, 6, 2, '$', 38, 26, 32, '$', '$', 23, 11, '$', '$', 30, 44, '$',
        10, 4, '$', 1, 27, 46, 37, '$', 21, 7, 17, 18, 45, 39, 35, '$', 13, 20, 19, 8, '$', 29, 28, '$']

k5tk = [7, 2, 6, 1, 3, 5, 0, 4]

trans = [18, 13, 22, 16, 6, 19, 5, 23, 1, 17, 12, 14, '$', 10, 0, 9, 7, 11, '$', '$', 4, '$', 8, 15, '$', '$', 34, 38, 37, 46, 47, 43, 41, 28, '$', 44, 42, 32, 24, 30, 45, 29, 35, 36, 25, '$', 26, 40]

def conn_to_server():
    s = ssh(host = host, user = user, password = password)
    io = s.run('sh')

    io.sendline(team_name)
    io.sendline(team_pass)

    io.recvuntil('You have solved ')
    lev_sol = int(io.recv(1).decode())
    print("Levels solved = ", lev_sol)
    io.sendline(str(4))
    #level specific
    io.sendline('read')
    io.recvuntil('it out though ..."\r\n\r\n> ')
    return io

def shift_left(k, nth_shifts): 
    s = "" 
    for i in range(nth_shifts): 
        for j in range(1,len(k)): 
            s = s + k[j] 
        s = s + k[0] 
        k = s 
        s = ""  
    return k

def enc(inp):
    out = ""
    for i in inp:
        out += chr(int(i,16)+ord('f'))
    return out

def dec(inp):
    out = ""
    for i in inp:
        out += hex(ord(i)-ord('f'))[2:]
    return out

def permute(k, arr, n): 
    permutation = "" 
    for i in range(0, n): 
        permutation = permutation + k[arr[i] - 1] 
    return permutation

def revp(inp, p):
    return hex(int(permute(bin(int(inp, 16))[2:].zfill(64), p, 64),2))[2:].zfill(16)

def mod_inp(inp):
    if inp == "password":
        return inp
    out = revp(inp, fp)
    out = enc(out)
    return out

def mod_out(inp):
    out = dec(inp)
    out = revp(out, iip)
    return out

def get_cip(inp, io):
    io.sendline(mod_inp(inp))
    io.recvuntil('It reads ...\r\n\t\t')
    out = io.recvuntil('\r\n\r\n\r\nPress').decode()[:-11]
    io.recvuntil('> ')
    io.sendline('c')
    return out

def get_pass(io):
    out = get_cip('password', io)
    out = dec(out)
    a, b = revp(out[:16], iip), revp(out[16:], iip)
    return a,b

def get_xor(xor_pt, io):
    ptx1 = bytes.fromhex(xor_pt[0])
    ptx2 = bytes.fromhex(xor_pt[1])
    inp, out = [], []
    inp.append(urandom(8).hex())
    inp.append(xor(bytes.fromhex(inp[0]), ptx1).hex())
    inp.append(xor(bytes.fromhex(inp[0]), ptx2).hex())
    inp.append(xor(bytes.fromhex(inp[1]), ptx2).hex())
    for i in range(4):
        out.append(mod_out(get_cip(inp[i], io)))
    return (inp, out)

#If quartet then input format : P, P ^ ptx1, P ^ ptx2, P ^ ptx1 ^ ptx2
def store_data(inp, out, inpf, outf, quar = False):
    if quar:
        open(inpf[0], 'a').write(inp[0]+','+inp[1]+'\n'+inp[2]+','+inp[3]+'\n')
        open(inpf[1], 'a').write(inp[0]+','+inp[2]+'\n'+inp[1]+','+inp[3]+'\n')
        open(outf[0], 'a').write(out[0]+','+out[1]+'\n'+out[2]+','+out[3]+'\n')
        open(outf[1], 'a').write(out[0]+','+out[2]+'\n'+out[1]+','+out[3]+'\n')
        return
    open(inpf, 'a').write(inp[0]+','+inp[1]+'\n')
    open(outf, 'a').write(out[0]+','+out[1]+'\n')

def collect_inputs(xor_pt, n, io):
    for cnt in range(n):
        print(cnt)
        i, o = get_xor(xor_pt = xor_pt, io = io)
        store_data(inp = i, out = o, inpf = ('inputs_c1.txt', 'inputs_c2.txt'), outf = ('outputs_c1.txt', 'outputs_c2.txt'), quar = True)

def read_files(*files):
    f = []
    for i in files:
        r = open(i, 'r').read().split('\n')[:-1]
        r = [(j.split(',')[0], j.split(',')[1]) for j in r]
        f.append(r)
    return f

def to_bits(inp, len):
    return bin(int(inp, 16))[2:].zfill(len)

def convert(inp):
    p = ''
    for i in inp:
        p += bin(i)[2:].zfill(6)
    return int(p, 2)

def change_dict(d, key):
    if key in d.keys():
        d[key] = d[key]+1
    else:
        d[key] = 1

def s_box_out(inp, box_no):
    c = (inp >> 1) & 0xf
    r = (inp & 1) | ((inp >> 4) & 2)
    return sbox[box_no][r][c]

def F(r0, key):
    i = permute(to_bits(r0, 32), exp, 48)
    i = [i[j:j+6] for j in range(0, 48, 6)]
    i = [s_box_out(int(i[j], 2)^key[j], j) if key[j]!='$' else '$' for j in range(8)]
    i = [bin(j)[2:].zfill(4) if j!='$' else '$$$$' for j in i]
    i = permute(''.join(i), per, 32)
    return i

def till_s_in_out(inp1, inp2, lbx):
    l1, r1 = inp1[:8], inp1[8:]
    l2, r2 = inp2[:8], inp2[8:]
    _in1 = bin(int(l1, 16))[2:].zfill(32)
    _in1 = permute(_in1, exp, 48)
    _in2 = bin(int(l2, 16))[2:].zfill(32)
    _in2 = permute(_in2, exp, 48)
    out = xor(bytes.fromhex(r1), bytes.fromhex(r2)).hex()
    out = xor(bytes.fromhex(out), bytes.fromhex(lbx)).hex()
    out = bin(int(out, 16))[2:].zfill(32)
    out = permute(out, inv_p, 32)
    return (_in1, _in2, out)

def find_6_bit_key_s_box(_inp1, _inp2, _out_xor, box_no):
    possible_keys = []
    for i in range(64):
        sI1 = i^int(_inp1, 2)
        sI2 = i^int(_inp2, 2)
        sO1 = s_box_out(sI1, box_no)
        sO2 = s_box_out(sI2, box_no)
        if sO1 ^ sO2 == int(_out_xor, 2):
            possible_keys.append(i)
    return possible_keys

def find_round_key(out, ex, selected_boxes):
    for i in range(len(out)):
        _s1, _s2, _so = till_s_in_out(out[i][0], out[i][1], ex)
        temp = []
        for j in selected_boxes:
            k = find_6_bit_key_s_box(_s1[j*6:(j+1)*6], _s2[j*6:(j+1)*6], _so[j*4:(j+1)*4], j)
            temp.append(k)
        temp = [convert(i) for i in list(product(*temp))]
        for i in temp:
            change_dict(key_dict, i)

def break_r6(out_tup, dx, cx):
    global key_dict, partial_key
    t = permute(to_bits(dx, 32), exp, 48)
    arr = [t[i:i+6] for i in range(0,48,6)]
    arr2 = ['0000' if i=='000000' else '1111' for i in arr]
    sel_box = [i for i in range(len(arr)) if arr[i]=='000000']
    Dx = int(permute(''.join(arr2), per, 32), 2)
    cx = int(cx, 16)
    approx_ex = hex(Dx ^ cx)[2:].zfill(8)
    find_round_key(out_tup, approx_ex, sel_box)
    _max = max(key_dict.values())
    _max = {i:key_dict[i] for i in key_dict.keys() if key_dict[i]==_max}
    assert len(_max.keys()) == 1
    partial_key.append(list(_max.keys())[0])
    key_dict = {}

#k1 obtained using 4008000004000000 and k2 using 0020000800000400
def obtain_42b(k1, k2):
    k1, k2 = bin(k1)[2:].zfill(30), bin(k2)[2:].zfill(30)
    k1 = [int(k1[i:i+6], 2) for i in range(0,30,6)]
    k2 = [int(k2[i:i+6], 2) for i in range(0,30,6)]
    print("Key obtained from first characterstic = ", k1)
    print("Key obtained from second characterstic = ", k2)
    assert k1[0] == k2[1]
    assert k1[1] == k2[3]
    assert k1[2] == k2[4]
    return [k2[0], k2[1], '$', k2[2], k2[3], k2[4], k1[3], k1[4]]

def start_cryptanalyis():
    _o = read_files('outputs_c1.txt')[0]
    break_r6(_o, '40080000', '04000000')
    _o = read_files('outputs_c2.txt')[0]
    break_r6(_o, '00200008', '00000400')
    return obtain_42b(*partial_key)

def filter_inputs():
    fk = ['$', k6[1], '$', '$', k6[4], k6[5], k6[6], k6[7]]
    _i, _o = read_files('inputs_c1.txt', 'outputs_c1.txt')
    cnt = 0
    for i in range(len(_o)):
        flag = 1
        _si1, _si2, _sox = till_s_in_out(_o[i][0], _o[i][1], '80c19346') #ex found in break_r6 function
        for ind, k in enumerate(fk):
            if k != '$':
                if s_box_out(int(_si1[6*ind:6*(ind+1)], 2)^k, ind) ^ s_box_out(int(_si2[6*ind:6*(ind+1)], 2)^k, ind) != int(_sox[4*ind:4*(ind+1)], 2):
                    flag = 0
                    break
        if flag == 1:
            cnt += 1
            store_data(inp = _i[i], out = _o[i], inpf = 'filtered_inp_c1.txt', outf = 'filtered_out_c1.txt')
    return cnt

def six_to_five(k6):
    k6 = [bin(i)[2:].zfill(6) if i != '$' else '$$$$$$' for i in k6]
    k6 = ''.join(k6)
    k5 = ['$']*48
    for i in range(48):
        if trans[i] != '$' and k6[i] != '$':
            k5[trans[i]] = k6[i]
    k5 = ''.join(k5)
    if kf == 1:
        return k5
    k5 = [k5[i:i+6] if '$' not in k5[i:i+6] else '$' for i in range(0,len(k5),6)]
    k5 = [int(i,2) if i != '$' else '$' for i in k5]
    return k5

def find_S3_r6_subbits():
    outp = read_files('filtered_out_c1.txt')[0]
    d = {}
    dx = '40080000'
    tk = [i for i in k6]
    for out in outp:
        fx = xor(bytes.fromhex(out[0][:8]), bytes.fromhex(out[1][:8])).hex()
        dfx = xor(bytes.fromhex(dx), bytes.fromhex(fx)).hex()
        dfx = to_bits(dfx, 32)
        for i in range(64):
            tk[2] = i
            temp = [i for i in tk]
            k5 = six_to_five(temp)
            e = decrypt_block(out[0], tk)
            es = decrypt_block(out[1], tk)
            e = e[:8]
            es = es[:8]
            E, Es = F(e, k5), F(es, k5)
            tu = ''
            for j in range(len(E)):
                if E[j] != '$':
                    tu += str(int(E[j]) ^ int(Es[j]) ^ int(dfx[j]))
            if int(tu, 2) == 0:
                change_dict(d, i)
    _max = max(d.values())
    _max = {i:d[i] for i in d.keys() if d[i]==_max}
    assert len(_max.keys()) == 1
    return list(_max.keys())[0]

def break_r5():
    global kf
    kf = 1
    d = {}
    outp = read_files('filtered_out_c1.txt')[0]
    k5 = six_to_five(k6)
    for out in outp:
        b60 = decrypt_block(out[0], k6)
        b61 = decrypt_block(out[1], k6)
        _si1, _si2, _sox = till_s_in_out(b60, b61, '40080000')
        sk = []
        for i in range(8):
            k = k5[i*6:(i+1)*6]
            if i == 0 or i == 3:
                xx = []
                for j in range(4):
                    z = bin(j)[2:].zfill(2)
                    k = k[:2] + z + k[4:6]
                    so1 = s_box_out(int(k, 2) ^ int(_si1[i*6:(i+1)*6], 2), i)
                    so2 = s_box_out(int(k, 2) ^ int(_si2[i*6:(i+1)*6], 2), i)
                    if so1 ^ so2 == int(_sox[i*4:(i+1)*4], 2):
                        xx.append(z)
                sk.append(xx)
            if i == 4 or i == 6:
                xx = []
                for j in range(2):
                    z = bin(j)[2:]
                    k = list(k)
                    k[3] = z
                    k = ''.join(k)
                    so1 = s_box_out(int(k, 2) ^ int(_si1[i*6:(i+1)*6], 2), i)
                    so2 = s_box_out(int(k, 2) ^ int(_si2[i*6:(i+1)*6], 2), i)
                    if so1 ^ so2 == int(_sox[i*4:(i+1)*4], 2):
                        xx.append(z)
                sk.append(xx)
            if i == 5:
                xx = []
                for j in range(4):
                    z = bin(j)[2:].zfill(2)
                    k = list(k)
                    k[1] = z[0]
                    k[3] = z[1]
                    k = ''.join(k)
                    so1 = s_box_out(int(k, 2) ^ int(_si1[i*6:(i+1)*6], 2), i)
                    so2 = s_box_out(int(k, 2) ^ int(_si2[i*6:(i+1)*6], 2), i)
                    if so1 ^ so2 == int(_sox[i*4:(i+1)*4], 2):
                        xx.append(z)
                sk.append(xx)
        sk = list(product(*sk))
        sk = [''.join(j) for j in sk]
        sk = [int(j,2) for j in sk]
        for j in sk:
            change_dict(d, j)
    _max = max(d.values())
    _max = {i:d[i] for i in d.keys() if d[i]==_max}
    assert len(_max.keys()) == 1
    return list(_max.keys())[0]

def recover_full_key(k5, k6):
    k6 = [bin(i)[2:].zfill(6) for i in k6]
    k6 = ''.join(k6)
    k = ['$']*64
    cnt = 0
    for i in range(64):
        if (i+1)%8 != 0:
            if k6tk[i] != '$':
                k[i] = k6[k6tk[i]]
            else:
                k[i] = k5[k5tk[cnt]]
                cnt += 1
    k = ''.join(k)
    k = [k[i:i+8] for i in range(0,64,8)]
    k = [i[:-1] for i in k]
    k = [i+'1' if i.count('1')%2!=0 else i+'0' for i in k]
    k = [int(i,2) for i in k]
    return k

def get_round_keys(k):
    global round_keys
    key = ''.join(bin(i)[2:].zfill(8) for i in k)
    key = permute(key, keyp, 56) 
    left = key[0:28]
    right = key[28:56]
    for i in range(0, 6): 
        left = shift_left(left, shift_table[i]) 
        right = shift_left(right, shift_table[i]) 
        combine_str = left + right 
        rk = permute(combine_str, key_comp, 48)
        rk = [rk[i:i+6] for i in range(0,48,6)]
        rk = [int(i,2) for i in rk]
        round_keys[i] = rk

def decrypt_block(block, key):
    r0 = block[:8]
    i = hex(int(F(r0, key),2))[2:].zfill(8)
    l0 = xor(bytes.fromhex(i), bytes.fromhex(block[8:])).hex()
    return l0+r0

def break_all(b):
    t = b
    for i in range(6):
        t = decrypt_block(t, round_keys[5-i])
    return t

if __name__ == '__main__':
    io = conn_to_server()
    print("-"*50)
    collect_inputs(pt_xor, 70, io)
    print("Collected 280 outputs.")
    print("-"*50)
    enc_pass = get_pass(io)
    print("Starting cryptanalysis...")
    k6 = start_cryptanalyis()
    print("42 bit round-6 subkey = ", k6)
    print("Filtering inputs...")
    cnt = filter_inputs()
    print("Filtered pairs left = ", cnt)
    print("Finding 6 left bits of round-6 subkey...")
    k6[2] = find_S3_r6_subbits()
    print("round-6 key = ", k6)
    print("Obtaining remaining 8 bits of key by cracking round-5...")
    kb8 = break_r5()
    kb8 = bin(kb8)[2:].zfill(8)
    k = recover_full_key(kb8, k6)
    print("Final Key = ", k)
    get_round_keys(k)
    print("Keys for each round are:")
    for i in range(6):
        print("R"+str(i)+" : ", round_keys[i])
    print("Encrypted password = ", ''.join(enc_pass))
    print("Decrypting password...")
    a, b = break_all(enc_pass[0]), break_all(enc_pass[1])
    c = dec(mod_inp(a)+mod_inp(b))
    c = [int(c[i:i+2], 16) for i in range(0, len(c), 2)]
    c = ''.join(chr(i) for i in c)
    print("Password = ", c)
