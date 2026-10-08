// sentri_top.v — SENTRI-256 integrasi v2 (cabang int-sha, karya tim)
// Top-level: hmac_avmm + key_guard + receipt_builder + doc_hash_ctrl + sha07_block (x2)
`default_nettype none
module sentri_top (
    input  wire        clk,
    input  wire        rst_n,

    // Avalon-MM slave (dari hmac_avmm)
    input  wire [5:0]  avs_address,
    input  wire [31:0] avs_writedata,
    input  wire        avs_write,
    input  wire        avs_read,
    output wire [31:0] avs_readdata,

    // Key provisioning (write-only)
    input  wire        key_wr_en,
    input  wire [255:0] key_wr_data,

    // Tamper & zeroize
    input  wire        tamper,
    input  wire        zeroize_cmd,

    // Status
    output wire        st_key_ready,
    output wire        st_locked,
    output wire        st_lockout,
    output wire        st_zeroized,

    // Receipt builder interface
    input  wire        rcpt_start,
    input  wire [7:0]  rcpt_version,
    input  wire        rcpt_verdict,
    input  wire [255:0] rcpt_doc_hash,
    input  wire [127:0] rcpt_nonce,
    output wire        sign_req,
    output wire [511:0] sign_payload,
    input  wire        sign_done,
    input  wire [511:0] sign_rs,
    output wire [911:0] receipt,
    output wire        receipt_valid,

    // Document hash interface (karya tim, Fase 1)
    input  wire        doc_start,
    input  wire [31:0] doc_word,
    input  wire        doc_word_valid,
    input  wire        doc_last,
    input  wire [31:0] doc_bytes,
    output wire        doc_accept,
    output wire [255:0] doc_digest,
    output wire        doc_done
);

    // Internal wires
    wire [255:0] kg_hmac;
    wire [255:0] kg_ecdsa;
    wire         kg_reject;
    wire [2:0]   kg_fail_cnt;

    // SHA-256 block #1 (untuk HMAC via hmac_ctrl, tidak dipakai langsung di sini)
    // SHA-256 block #2 (untuk doc_hash_ctrl, instansi baru)
    wire         sha_doc_busy;
    wire         sha_doc_done;
    wire [255:0] sha_doc_h_out;

    // Key Guard
    key_guard u_key_guard (
        .clk           (clk),
        .rst_n         (rst_n),
        .tamper_i      (tamper),
        .zeroize_cmd_i (zeroize_cmd),
        .key_wr_en_i   (key_wr_en),
        .key_wr_data_i (key_wr_data),
        .auth_fail_i   (1'b0),
        .key_ready_o   (st_key_ready),
        .locked_o      (st_locked),
        .lockout_o     (st_lockout),
        .zeroized_o    (st_zeroized),
        .reject_o      (kg_reject),
        .fail_cnt_o    (kg_fail_cnt),
        .key_hmac_o    (kg_hmac),
        .key_ecdsa_o   (kg_ecdsa)
    );

    // HMAC-AVMM wrapper (fork, tidak diubah)
    hmac_avmm u_hmac_avmm (
        .clk         (clk),
        .reset       (~rst_n),
        .avs_address (avs_address),
        .avs_read    (avs_read),
        .avs_readdata(avs_readdata),
        .avs_write   (avs_write),
        .avs_writedata(avs_writedata)
    );

    // Receipt Builder (karya tim)
    receipt_builder u_receipt (
        .clk            (clk),
        .rst_n          (rst_n),
        .start_i        (rcpt_start),
        .version_i      (rcpt_version),
        .verdict_i      (rcpt_verdict),
        .doc_hash_i     (rcpt_doc_hash),
        .nonce_i        (rcpt_nonce),
        .sign_req_o     (sign_req),
        .sign_payload_o (sign_payload),
        .sign_done_i    (sign_done),
        .sign_rs_i      (sign_rs),
        .receipt_o      (receipt),
        .receipt_valid_o(receipt_valid),
        .busy_o         ()
    );

       // SHA-256 block #2 untuk document hashing (instansi baru, Fase 1)
    wire [255:0] doc_sha_h_in;
    wire [511:0] doc_sha_data;
    wire         doc_sha_start;

    sha07_block u_sha_doc (
        .clk   (clk),
        .rst_n (rst_n),
        .start (doc_sha_start),
        .abort (1'b0),
        .h_in  (doc_sha_h_in),
        .block (doc_sha_data),
        .busy  (sha_doc_busy),
        .done  (sha_doc_done),
        .h_out (sha_doc_h_out)
    );

        // Document hash controller (karya tim, Fase 1)
    doc_hash_ctrl u_doc_hash (
        .clk          (clk),
        .rst_n        (rst_n),
        .start_i      (doc_start),
        .word_i       (doc_word),
        .word_valid_i (doc_word_valid),
        .last_word_i  (doc_last),
        .doc_bytes_i  (doc_bytes),
        .accept_o     (doc_accept),
        .sha_h_in_o   (doc_sha_h_in),
        .sha_data_o   (doc_sha_data),
        .sha_start_o  (doc_sha_start),
        .sha_busy_i   (sha_doc_busy),
        .sha_done_i   (sha_doc_done),
        .sha_h_out_i  (sha_doc_h_out),
        .digest_o     (doc_digest),
        .done_o       (doc_done),
        .busy_o       ()
    );

`ifdef COCOTB_SIM
initial begin
    $dumpfile("sentri_top.vcd");
    $dumpvars(0, sentri_top);
end
`endif
endmodule
`default_nettype wire
