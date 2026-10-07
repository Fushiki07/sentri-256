# test_receipt.py — SENTRI-256 (karya tim)
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles, Timer

VER   = 0x01
HASH  = 0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
NONCE = 0xaaaabbbbccccddddeeeeffff00001111
RS    = 0x0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de

def payload_of(ver, verdict, h, nonce):
    return (ver << 392) | (verdict << 391) | (h << 128) | nonce

async def reset(dut):
    dut.rst_n.value = 0
    dut.start_i.value = 0
    dut.version_i.value = 0
    dut.verdict_i.value = 0
    dut.doc_hash_i.value = 0
    dut.nonce_i.value = 0
    dut.sign_done_i.value = 0
    dut.sign_rs_i.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

async def build_one(dut, ver, verdict, h, nonce, rs):
    dut.version_i.value = ver
    dut.verdict_i.value = verdict
    dut.doc_hash_i.value = h
    dut.nonce_i.value = nonce
    dut.start_i.value = 1
    await RisingEdge(dut.clk)
    dut.start_i.value = 0
    for _ in range(20):
        if int(dut.sign_req_o.value) == 1: break
        await RisingEdge(dut.clk)
    assert int(dut.sign_req_o.value) == 1, "sign_req tidak naik"
    assert int(dut.busy_o.value) == 1, "busy harus aktif selama SIGN"
    pay = payload_of(ver, verdict, h, nonce)
    assert int(dut.sign_payload_o.value) == pay, "payload 512-bit salah"
    dut.sign_rs_i.value = rs
    dut.sign_done_i.value = 1
    await RisingEdge(dut.clk)          # edge E: SIGN menangkap rs
    dut.sign_done_i.value = 0
    await RisingEdge(dut.clk)          # edge E+1: pulsa valid aktif
    await Timer(1, units="ns")
    assert int(dut.receipt_valid_o.value) == 1, "pulsa receipt_valid hilang"
    assert int(dut.receipt_o.value) == (pay << 512) | rs, "resi != payload||rs"
    await RisingEdge(dut.clk)
    await Timer(1, units="ns")
    assert int(dut.receipt_valid_o.value) == 0, "valid harus satu siklus"
    assert int(dut.busy_o.value) == 0, "busy harus turun setelah DONE"

@cocotb.test()
async def test_payload_and_receipt(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await build_one(dut, VER, 1, HASH, NONCE, RS)

@cocotb.test()
async def test_verdict_zero(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await build_one(dut, VER, 0, HASH, NONCE, RS)

@cocotb.test()
async def test_back_to_back(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await build_one(dut, VER, 1, HASH, NONCE, RS)
    await build_one(dut, 0x02, 1, HASH ^ 0x5555, NONCE ^ 0xffff, RS ^ 0xaaaa)

@cocotb.test()
async def test_idle_quiet(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await ClockCycles(dut.clk, 20)
    assert int(dut.sign_req_o.value) == 0
    assert int(dut.receipt_valid_o.value) == 0
    assert int(dut.busy_o.value) == 0