# INTERFACE.md — kontrak internal sentri_top v2 (beku Fase 0)

## 1 SHA-HANDSHAKE (doc_hash_ctrl <-> sha07_block #2) — pemilik: Rafi — status: TERSAMBUNG, uji top 4/4 (cabang int-sha)
Port sha07_block (src/sha07_block.v): clk, rst_n, start, abort, h_in[255:0], block[511:0], busy, done, h_out[255:0].
Pemetaan: sha_start_o->start; sha_h_in_o->h_in; sha_data_o->block; busy->sha_busy_i; done->sha_done_i; h_out->sha_h_out_i; abort=1'b0.
Port top jalur dokumen: doc_start, doc_word[31:0], doc_word_valid, doc_last, doc_bytes[31:0], doc_accept, doc_digest[255:0], doc_done.

## 2 SIGN-REQ (receipt_builder <-> ecdsa256_wrapper) — pemilik: Naufal — status: MENUNGGU penyambungan (cabang int-sign)
Sisi receipt_builder: sign_req_o (out,1), sign_payload_o (out,512), sign_done_i (in,1), sign_rs_i (in,512).
Sisi ecdsa256_wrapper: [ISI NAUFAL: port kunci privat, masukan pesan/hash, start, busy/done, keluaran r dan s]
Titik keputusan: bila wrapper hanya membuka K×G tanpa tanda tangan penuh, T2 = jalur tanda tangan parsial (r dari fabric, s dari model HPS) dan wajib dilabel jujur.

## 3 KEY-PATH (key_guard -> konsumen) — pemilik: Naufal
key_hmac_o[255:0] ke mux lapisan tim (Fase 3); key_ecdsa_o[255:0] ke masukan kunci ecdsa256_wrapper.
Aturan: tidak ada jalur baca balik; zeroize menghapus keduanya.

## Aturan perubahan
Perubahan file ini butuh kesepakatan kedua pemilik dan commit baru.
