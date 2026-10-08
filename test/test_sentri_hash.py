# test_sentri_hash.py — SENTRI-256 (karya tim)
# Jalur hash dokumen di sentri_top v2: word 32-bit masuk, digest keluar dari RTL asli.
import cocotb
import hashlib
import struct
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

async def reset(dut):
    dut.rst_n.value = 0
    dut.avs_address.value = 0
    dut.avs_writedata.value = 0
    dut.avs_write.value = 0
    dut.avs_read.value = 0
    dut.key_wr_en.value = 0
    dut.key_wr_data.value = 0
    dut.tamper.value = 0
    dut.rcpt_start.value = 0
    dut.rcpt_version.value = 0
    dut.rcpt_verdict.value = 0
    dut.rcpt_doc_hash.value = 0
    dut.rcpt_nonce.value = 0
    dut.sign_done.value = 0
    dut.sign_rs.value = 0
    dut.doc_start.value = 0
    dut.doc_word.value = 0
    dut.doc_word_valid.value = 0
    dut.doc_last.value = 0
    dut.doc_bytes.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

async def hash_document(dut, msg):
    dut.doc_bytes.value = len(msg)
    dut.doc_start.value = 1
    await RisingEdge(dut.clk)
    dut.doc_start.value = 0
    padded = msg + b'\x00' * ((4 - len(msg) % 4) % 4)
    words = [struct.unpack('>I', padded[i:i+4])[0] for i in range(0, len(padded), 4)]
    for i, w in enumerate(words):
        while True:
            await RisingEdge(dut.clk)
            if int(dut.doc_accept.value) == 1:
                break
        dut.doc_word.value = w
        dut.doc_word_valid.value = 1
        dut.doc_last.value = 1 if i == len(words) - 1 else 0
    await RisingEdge(dut.clk)
    dut.doc_word_valid.value = 0
    dut.doc_last.value = 0
    for _ in range(200000):
        if int(dut.doc_done.value) == 1:
            d = int(dut.doc_digest.value)
            await RisingEdge(dut.clk)
            return d
        await RisingEdge(dut.clk)
    raise RuntimeError("timeout menunggu doc_done")

async def run_case(dut, msg):
    await reset(dut)
    got = await hash_document(dut, msg)
    exp = int(hashlib.sha256(msg).hexdigest(), 16)
    assert got == exp, f"len={len(msg)}: got {got:064x}, expected {exp:064x}"

@cocotb.test()
async def test_doc_64(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"E" * 64)

@cocotb.test()
async def test_doc_100(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await run_case(dut, b"F" * 100)

@cocotb.test()
async def test_doc_200_random(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    import random
    random.seed(256)
    msg = bytes(random.getrandbits(8) for _ in range(200))
    await run_case(dut, msg)

@cocotb.test()
async def test_idle_quiet(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    for _ in range(30):
        await RisingEdge(dut.clk)
        assert int(dut.doc_done.value) == 0
        assert int(dut.doc_accept.value) == 0