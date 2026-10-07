// doc_hash_ctrl.v — SENTRI-256 (karya tim, Apache-2.0)
// Pengendali hash dokumen multi-blok dengan padding SHA-256 standar.
// Mesin kompresi berada di luar modul; testbench menyediakan model SHA-256.
`default_nettype none
module doc_hash_ctrl (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start_i,
    input  wire [31:0]  word_i,
    input  wire         word_valid_i,
    input  wire         last_word_i,
    input  wire [31:0]  doc_bytes_i,
    output wire         accept_o,
    output reg  [255:0] sha_h_in_o,
    output reg  [511:0] sha_data_o,
    output reg          sha_start_o,
    input  wire         sha_busy_i,
    input  wire         sha_done_i,
    input  wire [255:0] sha_h_out_i,
    output reg  [255:0] digest_o,
    output reg          done_o,
    output reg          busy_o
);
    reg [2:0] state;
    localparam [2:0] IDLE=3'd0, COLLECT=3'd1, PADTAIL=3'd2, PADFULL=3'd3,
                     HASH=3'd4, WAIT=3'd5, DONE=3'd6;

    reg [1:0] after_hash;
    localparam [1:0] AH_COLLECT=2'd0, AH_DONE=2'd1, AH_PADFULL=2'd2;

    reg [511:0] block_buf;
    reg [6:0]   byte_cnt;
    reg [255:0] h_cur;
    reg [31:0]  len_reg;
    reg         pad2_has80;

    wire [63:0] bit_len  = {32'b0, len_reg} << 3;
    wire [5:0]  pad_pos  = len_reg[5:0];
    wire [9:0]  wr_base  = 10'd511 - ({3'b000, byte_cnt} * 10'd8);
    wire [9:0]  pad_base = 10'd511 - ({4'b00,  pad_pos } * 10'd8);

    localparam [255:0] IV = 256'h6a09e667_bb67ae85_3c6ef372_a54ff53a_510e527f_9b05688c_1f83d9ab_5be0cd19;

    assign accept_o = (state == COLLECT);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;   block_buf <= 512'h0;  byte_cnt <= 7'd0;
            h_cur <= 256'h0; len_reg <= 32'd0;     after_hash <= AH_COLLECT;
            pad2_has80 <= 1'b0;
            sha_h_in_o <= 256'h0; sha_data_o <= 512'h0; sha_start_o <= 1'b0;
            digest_o <= 256'h0; done_o <= 1'b0; busy_o <= 1'b0;
        end else begin
            done_o      <= 1'b0;
            sha_start_o <= 1'b0;
            case (state)
                IDLE: if (start_i) begin
                    h_cur     <= IV;
                    len_reg   <= doc_bytes_i;
                    block_buf <= 512'h0;
                    byte_cnt  <= 7'd0;
                    busy_o    <= 1'b1;
                    state     <= COLLECT;
                end

                COLLECT: begin
                    if (word_valid_i) begin
                        block_buf[wr_base -: 32] <= word_i;
                        byte_cnt <= byte_cnt + 7'd4;
                        if (last_word_i) begin
                            if (byte_cnt + 7'd4 == 7'd64 && len_reg[5:0] == 6'd0) begin
                                pad2_has80 <= 1'b1;
                                after_hash <= AH_PADFULL;
                                state      <= HASH;
                            end else begin
                                state <= PADTAIL;
                            end
                        end else if (byte_cnt + 7'd4 == 7'd64) begin
                            after_hash <= AH_COLLECT;
                            state      <= HASH;
                        end
                    end else if (last_word_i) begin
                        state <= PADTAIL;
                    end
                end

                PADTAIL: begin
                    block_buf[pad_base -: 8] <= 8'h80;
                    if (pad_pos <= 6'd55) begin
                        block_buf[63:0] <= bit_len;
                        after_hash <= AH_DONE;
                    end else begin
                        pad2_has80 <= 1'b0;
                        after_hash <= AH_PADFULL;
                    end
                    state <= HASH;
                end

                PADFULL: begin
                    if (pad2_has80)
                        block_buf[511 -: 8] <= 8'h80;
                    block_buf[63:0] <= bit_len;
                    after_hash      <= AH_DONE;
                    state           <= HASH;
                end

                HASH: begin
                    sha_h_in_o  <= h_cur;
                    sha_data_o  <= block_buf;
                    sha_start_o <= 1'b1;
                    state       <= WAIT;
                end

                WAIT: if (sha_done_i) begin
                    h_cur <= sha_h_out_i;
                    case (after_hash)
                        AH_COLLECT: begin
                            block_buf <= 512'h0;
                            byte_cnt  <= 7'd0;
                            state     <= COLLECT;
                        end
                        AH_PADFULL: begin
                            block_buf <= 512'h0;
                            byte_cnt  <= 7'd0;
                            state     <= PADFULL;
                        end
                        default: state <= DONE;
                    endcase
                end

                DONE: begin
                    digest_o <= h_cur;
                    done_o   <= 1'b1;
                    busy_o   <= 1'b0;
                    state    <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end
endmodule
`default_nettype wire