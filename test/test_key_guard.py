# test_key_guard.py — SENTRI-256 (karya tim)
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles, Timer

KEY  = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
KEY2 = 0xdeadbeefcafef00d112233445566778899aabbccddeeff001122334455667788

async def reset(dut):
    dut.rst_n.value = 0
    dut.tamper_i.value = 0
    dut.zeroize_cmd_i.value = 0
    dut.key_wr_en_i.value = 0
    dut.key_wr_data_i.value = 0
    dut.auth_fail_i.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

async def write_key(dut, key):
    dut.key_wr_data_i.value = key
    dut.key_wr_en_i.value = 1
    await RisingEdge(dut.clk)
    dut.key_wr_en_i.value = 0
    await RisingEdge(dut.clk)

async def fail_pulse(dut):
    dut.auth_fail_i.value = 1
    await RisingEdge(dut.clk)
    dut.auth_fail_i.value = 0
    await RisingEdge(dut.clk)

@cocotb.test()
async def test_write_and_lock(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    assert int(dut.key_ready_o.value) == 0, "kunci belum boleh siap setelah reset"
    await write_key(dut, KEY)
    assert int(dut.locked_o.value) == 1, "lock bit harus ter-set setelah tulis"
    assert int(dut.key_ready_o.value) == 1
    assert int(dut.key_hmac_o.value) == KEY, "kunci internal HMAC salah"
    assert int(dut.key_ecdsa_o.value) == KEY, "kunci internal ECDSA salah"

@cocotb.test()
async def test_second_write_rejected(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await write_key(dut, KEY)
    # percobaan tulis kedua harus DITOLAK (write-only + lock bit)
    dut.key_wr_data_i.value = KEY2
    dut.key_wr_en_i.value = 1
    await RisingEdge(dut.clk)
    await Timer(1, units="ns")        # <-- TAMBAH: biarkan NBA settle, pulsa reject masih aktif
    reject_seen = int(dut.reject_o.value)
    dut.key_wr_en_i.value = 0
    await RisingEdge(dut.clk)
    assert reject_seen == 1, "tulis kedua harus memicu pulsa reject"
    assert int(dut.key_hmac_o.value) == KEY, "kunci tidak boleh berubah"

@cocotb.test()
async def test_lockout_after_three_fails(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await write_key(dut, KEY)
    await fail_pulse(dut)
    await fail_pulse(dut)
    assert int(dut.lockout_o.value) == 0, "belum lockout pada gagal ke-2"
    await fail_pulse(dut)
    assert int(dut.lockout_o.value) == 1, "lockout harus aktif pada gagal ke-3"
    assert int(dut.key_ready_o.value) == 0
    assert int(dut.key_hmac_o.value) == 0, "kunci harus dimask saat lockout"

@cocotb.test()
async def test_tamper_zeroize(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await write_key(dut, KEY)
    dut.tamper_i.value = 1
    await ClockCycles(dut.clk, 5)   # synchronizer + zeroize
    assert int(dut.zeroized_o.value) == 1, "zeroized harus sticky"
    assert int(dut.key_hmac_o.value) == 0, "kunci harus nol setelah tamper"
    assert int(dut.key_ecdsa_o.value) == 0
    dut.tamper_i.value = 0
    await ClockCycles(dut.clk, 3)
    assert int(dut.zeroized_o.value) == 1, "zeroized tetap sticky setelah tamper lepas"
    assert int(dut.key_ready_o.value) == 0
    await write_key(dut, KEY2)      # provisioning ulang harus ditolak
    assert int(dut.key_ready_o.value) == 0

@cocotb.test()
async def test_zeroize_cmd(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    await write_key(dut, KEY)
    dut.zeroize_cmd_i.value = 1
    await RisingEdge(dut.clk)
    dut.zeroize_cmd_i.value = 0
    await ClockCycles(dut.clk, 2)
    assert int(dut.zeroized_o.value) == 1
    assert int(dut.key_hmac_o.value) == 0
