// receipt_builder.v — SENTRI-256 (karya tim, Apache-2.0)
// Menyusun payload resi 50 byte {versi|verdict|reserved|hash|nonce},
// meminta penandatanganan, lalu menggabungkan tanda tangan r||s.
// Catatan integrasi: orchestrator wajib menunggu busy_o=0 sebelum start_i.
`default_nettype none
module receipt_builder (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start_i,
    input  wire [7:0]   version_i,
    input  wire         verdict_i,
    input  wire [255:0] doc_hash_i,
    input  wire [127:0] nonce_i,
    output reg          sign_req_o,
    output wire [511:0] sign_payload_o,
    input  wire         sign_done_i,
    input  wire [511:0] sign_rs_i,
    output wire [911:0] receipt_o,
    output reg          receipt_valid_o,
    output reg          busy_o
);
    reg [399:0] payload_q;
    reg [511:0] rs_q;
    reg [1:0]   state;
    localparam  IDLE = 2'd0, SIGN = 2'd1, DONE = 2'd2;

    assign sign_payload_o = {112'b0, payload_q};
    assign receipt_o      = {payload_q, rs_q};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;  payload_q <= 400'b0;  rs_q <= 512'b0;
            sign_req_o <= 1'b0;  receipt_valid_o <= 1'b0;  busy_o <= 1'b0;
        end else begin
            receipt_valid_o <= 1'b0;
            case (state)
                IDLE: if (start_i) begin
                    payload_q  <= {version_i, verdict_i, 7'b0, doc_hash_i, nonce_i};
                    sign_req_o <= 1'b1;
                    busy_o     <= 1'b1;
                    state      <= SIGN;
                end
                SIGN: if (sign_done_i) begin
                    rs_q       <= sign_rs_i;
                    sign_req_o <= 1'b0;
                    state      <= DONE;
                end
                DONE: begin
                    receipt_valid_o <= 1'b1;
                    busy_o          <= 1'b0;
                    state           <= IDLE;
                end
                default: state <= IDLE;
            endcase
        end
    end
endmodule
`default_nettype wire