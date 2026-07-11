// zip_kat_test.cc — standalone functional KAT for snort3's ZIP local-file-header decompressor
// (src/decompress/file_decomp_zip.cc), the code fuzzed by file_decomp_zip_fuzz.
//
// This program is NOT a fuzzer: it builds a well-formed ZIP local-header BODY (the bytes that
// follow the 4-byte "PK\x03\x04" signature — file_decomp_zip.cc's own comment notes the signature
// is matched by the generic dispatcher upstream, so File_Decomp_Init_ZIP() starts right after it),
// containing a real DEFLATE stream compressing a KNOWN plaintext, runs it through the real
// production decompressor (File_Decomp_Init_ZIP + File_Decomp_ZIP, unmodified), and asserts the
// COMPUTED decompressed output matches the known plaintext byte-for-byte (a known-answer test).
// A no-op/exit(0) neuter of this binary produces NO "ZIP_KAT" marker line, which is what
// mayhem/test.sh's sabotage-detection check relies on (SPEC section 6.3).
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <zlib.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "decompress/file_decomp_zip.h"

using namespace snort;

static std::vector<uint8_t> deflate_raw(const std::string& plaintext)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    int rc = deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    assert(rc == Z_OK);

    std::vector<uint8_t> out(plaintext.size() + 128);
    zs.next_in = (Bytef*)plaintext.data();
    zs.avail_in = (uInt)plaintext.size();
    zs.next_out = out.data();
    zs.avail_out = (uInt)out.size();

    rc = deflate(&zs, Z_FINISH);
    assert(rc == Z_STREAM_END);
    out.resize(out.size() - zs.avail_out);
    deflateEnd(&zs);
    return out;
}

// Build the local-header BODY (everything after the 4-byte "PK\x03\x04" signature) for one
// stored file, per the ZIP_STATE_* layout in file_decomp_zip.cc:
//   version(2, skipped) bitflag(2) method(2) modtime(2)+moddate(2)+crc(4, skipped)
//   compressed_size(4) uncompressed_size(4, skipped) filename_len(2) extra_len(2)
//   filename(filename_len) extra(extra_len) <compressed stream>
static std::vector<uint8_t> build_zip_body(const std::string& filename,
    const std::vector<uint8_t>& compressed, uint16_t bitflag)
{
    std::vector<uint8_t> b;
    auto put16 = [&](uint16_t v) { b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF); };
    auto put32 = [&](uint32_t v)
    {
        b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF);
        b.push_back((v >> 16) & 0xFF); b.push_back((v >> 24) & 0xFF);
    };

    put16(0x0014);                       // version needed to extract (skipped by parser)
    put16(bitflag);                      // general purpose bit flag
    put16(8);                            // compression method = 8 (deflate)
    put16(0); put16(0); put32(0);        // modtime, moddate, crc-32 (all skipped)
    put32((uint32_t)compressed.size());  // compressed size
    put32(0);                            // uncompressed size (skipped by parser)
    put16((uint16_t)filename.size());    // filename length
    put16(0);                            // extra field length
    for (char c : filename) b.push_back((uint8_t)c);
    b.insert(b.end(), compressed.begin(), compressed.end());
    return b;
}

// Run one ZIP local-header body through the real decompressor and return the decompressed bytes.
static std::vector<uint8_t> run_zip_decomp(const std::vector<uint8_t>& body, fd_status_t& status)
{
    fd_session_t* fd = File_Decomp_New();
    fd->File_Type = FILE_TYPE_ZIP;
    fd->Next_In = body.data();
    fd->Avail_In = (uint32_t)body.size();

    std::vector<uint8_t> out_buf(65536, 0);
    fd->Next_Out = out_buf.data();
    fd->Avail_Out = (uint32_t)out_buf.size();

    File_Decomp_Init_ZIP(fd);
    status = File_Decomp_ZIP(fd);

    uint32_t total_out = fd->Total_Out;
    std::vector<uint8_t> result(out_buf.begin(), out_buf.begin() + total_out);

    File_Decomp_End_ZIP(fd);
    File_Decomp_Free(fd);
    return result;
}

int main()
{
    int failures = 0;

    // --- KAT 1: a normal, complete DEFLATE stream decompresses to the EXACT known plaintext. ---
    {
        const std::string plaintext =
            "MAYHEM_KAT_snort3_file_decomp_zip 0123456789 the quick brown fox jumps";
        auto compressed = deflate_raw(plaintext);
        auto body = build_zip_body("test.txt", compressed, /*bitflag*/0x0000);

        // file_decomp_zip.cc's state machine mirrors EVERY input byte to the output stream as it
        // parses (Move_1/Move_N), not just the inflated payload — so a single, complete entry with
        // no trailing data produces: <local-header-body bytes verbatim> <inflated plaintext>, and
        // (since there is no next entry to read) the state machine ends the call BLOCKED ON INPUT
        // (File_Decomp_BlockIn) having fully drained Avail_In — that is this harness's SUCCESS case.
        std::vector<uint8_t> expected(body.begin(), body.end() - (long)compressed.size());
        expected.insert(expected.end(), plaintext.begin(), plaintext.end());

        fd_status_t status;
        auto out = run_zip_decomp(body, status);

        bool ok = (status == File_Decomp_BlockIn)
            && (out.size() == expected.size())
            && (memcmp(out.data(), expected.data(), expected.size()) == 0);

        printf("ZIP_KAT case=roundtrip status=%d out_len=%zu expected_len=%zu match=%d\n",
            (int)status, out.size(), expected.size(), ok ? 1 : 0);
        if (!ok) failures++;
    }

    // --- KAT 2: a different plaintext/filename must decompress to a DIFFERENT, still-correct
    //     value — proves the harness is exercising real deflate decompression, not returning a
    //     constant or echoing the input unchanged. ---
    {
        const std::string plaintext2 = "second-distinct-payload-for-snort3-zip-KAT-check!!";
        auto compressed2 = deflate_raw(plaintext2);
        auto body2 = build_zip_body("other.bin", compressed2, /*bitflag*/0x0000);

        std::vector<uint8_t> expected2(body2.begin(), body2.end() - (long)compressed2.size());
        expected2.insert(expected2.end(), plaintext2.begin(), plaintext2.end());

        fd_status_t status2;
        auto out2 = run_zip_decomp(body2, status2);

        bool ok2 = (status2 == File_Decomp_BlockIn)
            && (out2.size() == expected2.size())
            && (memcmp(out2.data(), expected2.data(), expected2.size()) == 0);

        printf("ZIP_KAT case=distinct-payload status=%d out_len=%zu expected_len=%zu match=%d\n",
            (int)status2, out2.size(), expected2.size(), ok2 ? 1 : 0);
        if (!ok2) failures++;
    }

    printf("ZIP_KAT SUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
