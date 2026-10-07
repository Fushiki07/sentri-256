// key_guard.v — SENTRI-256 (karya tim, Apache-2.0)
// Key vault write-only: lock bit, lockout setelah N gagal, zeroize saat tamper.
`default_nettype none
module key_guard #(
    parameter integer LOCKOUT_LIMIT = 3
)(
    input  wire         clk,
    input  wire         rst_n,

    // tamper / zeroize
    input  wire         tamper_i,        // GPIO tamper, active-high
    input  wire         zeroize_cmd_i,   // perintah zeroize sinkron

    // jalur provisioning (HANYA tulis, tidak ada jalur baca)
    input  wire         key_wr_en_i,
    input  wire [255:0] key_wr_data_i,

    // pulsa kegagalan autentikasi dari orkestrator
    input  wire         auth_fail_i,

    // status
    output reg          key_ready_o,
    output reg          locked_o,
    output reg          lockout_o,
    output reg          zeroized_o,
    output reg          reject_o,        // pulsa: percobaan tulis ditolak
    output reg  [2:0]   fail_cnt_o,

    // keluaran kunci INTERNAL fabric (tidak boleh diroute ke bus)
    output wire [255:0] key_hmac_o,
    output wire [255:0] key_ecdsa_o
);
    reg [255:0] key_reg;
    reg         tamper_q1, tamper_q2;
    localparam  [2:0] LIMIT = LOCKOUT_LIMIT;

    // synchronizer 2-FF untuk tamper asinkron
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tamper_q1 <= 1'b0;
            tamper_q2 <= 1'b0;
        end else begin
            tamper_q1 <= tamper_i;
            tamper_q2 <= tamper_q1;
        end
    end

    wire zeroize_now = tamper_q2 | zeroize_cmd_i;
    wire write_ok    = key_wr_en_i & ~locked_o & ~lockout_o & ~zeroized_o;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg     <= 256'h0;
            key_ready_o <= 1'b0;
            locked_o    <= 1'b0;
            lockout_o   <= 1'b0;
            zeroized_o  <= 1'b0;
            reject_o    <= 1'b0;
            fail_cnt_o  <= 3'd0;
        end else if (zeroize_now) begin
            // ZEROIZE: kunci dan seluruh status sensitif dihapus
            key_reg     <= 256'h0;
            key_ready_o <= 1'b0;
            locked_o    <= 1'b0;
            lockout_o   <= 1'b0;
            zeroized_o  <= 1'b1;   // sticky sampai reset
            reject_o    <= 1'b0;
            fail_cnt_o  <= 3'd0;
        end else begin
            reject_o <= 1'b0;
            if (key_wr_en_i) begin
                if (write_ok) begin
                    key_reg     <= key_wr_data_i;
                    locked_o    <= 1'b1;   // lock bit: tulis berikut ditolak
                    key_ready_o <= 1'b1;
                end else begin
                    reject_o <= 1'b1;      // pulsa penolakan
                end
            end
            if (auth_fail_i && !lockout_o && key_ready_o) begin
                fail_cnt_o <= fail_cnt_o + 3'd1;
                if (fail_cnt_o + 3'd1 >= LIMIT) begin
                    lockout_o   <= 1'b1;
                    key_ready_o <= 1'b0;   // kunci dimask, tidak bisa dipakai
                end
            end
        end
    end

    // masking: kunci hanya muncul di keluaran internal saat siap
    assign key_hmac_o  = key_ready_o ? key_reg : 256'h0;
    assign key_ecdsa_o = key_ready_o ? key_reg : 256'h0;
endmodule
`default_nettype wire