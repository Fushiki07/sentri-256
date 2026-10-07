# test_doc_hash.py — SENTRI-256 (karya tim)
import cocotb
import hashlib
import struct
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

M = 0xffffffff
K = [
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

def rotr(x, n): return ((x >> n) | (x << (32 - n))) & M

def compress(h, block):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3)
        s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & M)
    a,b,c,d,e,f,g,hh = h
    for i in range(64):
        S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (hh + S1 + ch + K[i] + w[i]) & M
        S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & M
        hh,g,f,e = g,f,e,(d + t1) & M
        d,c,b,a = c,b,a,(t1 + t2) & M
    return [(x + y) & M for x, y in zip(h, [a,b,c,d,e,f,g,hh])]

async def sha_engine(dut, latency=30):
    while True:
        await RisingEdge(dut.clk)
        if int(dut.rst_n.value) != 1:
            continue
        if int(dut.sha_start_o.value) == 1:
            hv = int(dut.sha_h_in_o.value)
            data = int(dut.sha_data_o.value)
            h = [(hv >> (224 - 32*i)) & M for i in range(8)]
            out = compress(h, data.to_bytes(64, 'big'))
            ov = 0
            for x in out: ov = (ov << 32) | x
            dut.sha_busy_i.value = 1
            for _ in range(latency):
                await RisingEdge(dut.clk)
            dut.sha_h_out_i.value = ov
            dut.sha_done_i.value = 1
            await RisingEdge(dut.clk)
            dut.sha_done_i.value = 0
            dut.sha_busy_i.value = 0

async def reset(dut):
    dut.rst_n.value = 0
    dut.start_i.value = 0
    dut.word_i.value = 0
    dut.word_valid_i.value = 0
    dut.last_word_i.value = 0
    dut.doc_bytes_i.value = 0
    dut.sha_busy_i.value = 0
    dut.sha_done_i.value = 0
    dut.sha_h_out_i.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

async def hash_message(dut, msg):
    for _ in range(20):
        if int(dut.busy_o.value) == 0: break
        await RisingEdge(dut.clk)
    dut.doc_bytes_i.value = len(msg)
    dut.start_i.value = 1
    await RisingEdge(dut.clk)
    dut.start_i.value = 0

    padded = msg + b'\x00' * ((4 - len(msg) % 4) % 4)
    words = [struct.unpack('>I', padded[i:i+4])[0] for i in range(0, len(padded), 4)]

    async def present(w, last, valid):
        while True:
            await RisingEdge(dut.clk)
            if int(dut.accept_o.value) == 1:
                break
        dut.word_i.value = w
        dut.word_valid_i.value = valid
        dut.last_word_i.value = last

    if not words:
        await present(0, 1, 0)
        await RisingEdge(dut.clk)
        dut.last_word_i.value = 0
    else:
        for i, w in enumerate(words):
            await present(w, 1 if i == len(words)-1 else 0, 1)
        await RisingEdge(dut.clk)
        dut.word_valid_i.value = 0
        dut.last_word_i.value = 0

    for _ in range(100000):
        if int(dut.done_o.value) == 1:
            d = int(dut.digest_o.value)
            await RisingEdge(dut.clk)
            return d
        await RisingEdge(dut.clk)
    raise RuntimeError("timeout menunggu done_o")

async def run_case(dut, msg):
    await reset(dut)
    cocotb.start_soon(sha_engine(dut))
    got = await hash_message(dut, msg)
    exp = int(hashlib.sha256(msg).hexdigest(), 16)
    assert got == exp, f"len={len(msg)}: got {got:064x}, expected {exp:064x}"

@cocotb.test()
async def test_empty(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"")

@cocotb.test()
async def test_abc(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"abc")

@cocotb.test()
async def test_55_bytes(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"B" * 55)

@cocotb.test()
async def test_56_bytes(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"C" * 56)

@cocotb.test()
async def test_63_bytes(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"D" * 63)

@cocotb.test()
async def test_64_bytes(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"E" * 64)

@cocotb.test()
async def test_100_bytes(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"F" * 100)

@cocotb.test()
async def test_random_200(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    import random
    random.seed(256)
    msg = bytes(random.getrandbits(8) for _ in range(200))
    await run_case(dut, msg)