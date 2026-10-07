# test_dbg64.py — debug jalur kelipatan 64 byte
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
from test_doc_hash import compress, reset, hash_message, M

IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]

CAP = []

async def dbg_engine(dut, latency=30):
    while True:
        await RisingEdge(dut.clk)
        if int(dut.rst_n.value) != 1:
            continue
        if int(dut.sha_start_o.value) == 1:
            hv = int(dut.sha_h_in_o.value)
            data = int(dut.sha_data_o.value)
            CAP.append((hv, data))
            h = [(hv >> (224-32*i)) & M for i in range(8)]
            out = compress(h, data.to_bytes(64,'big'))
            ov = 0
            for x in out: ov = (ov<<32)|x
            dut.sha_busy_i.value = 1
            for _ in range(latency):
                await RisingEdge(dut.clk)
            dut.sha_h_out_i.value = ov
            dut.sha_done_i.value = 1
            await RisingEdge(dut.clk)
            dut.sha_done_i.value = 0
            dut.sha_busy_i.value = 0

@cocotb.test()
async def test_dbg64(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)
    cocotb.start_soon(dbg_engine(dut))
    msg = b"E"*64
    got = await hash_message(dut, msg)
    exp_blocks = [msg, bytes([0x80]) + b"\x00"*55 + (512).to_bytes(8,'big')]
    h = IV[:]
    for i, blk in enumerate(exp_blocks):
        exp_data = int.from_bytes(blk,'big')
        exp_hin = 0
        for x in h: exp_hin = (exp_hin<<32)|x
        if i < len(CAP):
            cap_hin, cap_data = CAP[i]
        else:
            cap_hin, cap_data = 0, 0
        cocotb.log.info("BLK%d h_in  cap=%064x exp=%064x match=%s", i, cap_hin, exp_hin, cap_hin==exp_hin)
        cocotb.log.info("BLK%d data  cap=%0128x", i, cap_data)
        cocotb.log.info("BLK%d data  exp=%0128x", i, exp_data)
        h = compress(h, blk)
    cocotb.log.info("CAP count=%d digest got=%064x", len(CAP), got)