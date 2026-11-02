#include <stdint.h>
#include <stdio.h>

// Reads a big-endian (ICC byte order) uint32 from p.
static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

// Finds the ST 2094-50 payload of the 'HAGC' tag and the 4 bytes of 'cicp' tag
// data in the ICC profile in buf[0..len). On success, points hagc/cicp into buf
// and sets hagc_size/cicp_size. If the profile fails basic validation (the same
// checks as skcms) or a tag is absent or malformed, its outputs are unchanged.
void icc_find_hagc_cicp(const uint8_t* buf, size_t len,
                        const uint8_t** hagc, size_t* hagc_size,
                        const uint8_t** cicp, size_t* cicp_size) {
  // Make sure header and tag size will fit.
  const uint32_t kHeaderSize = 128;
  if (len < kHeaderSize + 4) return;

  // Read signature and verify is an ICC profile.
  const uint32_t kSig_acsp = 0x61637370;
  uint32_t signature = be32(buf + 36);
  if (signature != kSig_acsp) return;

  // Read profile size and verify it fits in the buffer.
  uint64_t size = be32(buf);
  if (size > len) return;

  // Read major version and verify it is supported.
  uint8_t version = buf[8];
  if (version > 4) return;

  // Read tag count and verify the tag table fits in the profile.
  const uint32_t kTagEntrySize = 12;
  uint64_t tag_count = be32(buf + kHeaderSize);
  uint64_t tags_end  = kHeaderSize + 4 + kTagEntrySize * tag_count;
  if (size < tags_end) return;

  // Search for the CICP and HAGC tags with the expected types.
  const uint8_t* cicp_tag = NULL;
  const uint8_t* hagc_tag = NULL;
  for (uint64_t i = 0; i < tag_count; i++) {
    const uint8_t* entry = buf + kHeaderSize + 4 + kTagEntrySize * i;
    uint32_t tag_sig    = be32(entry);
    uint32_t tag_offset = be32(entry + 4);
    uint32_t tag_size   = be32(entry + 8);
    uint64_t tag_end    = (uint64_t)tag_offset + tag_size;

    // Fail if the tag is too small to hold a type or overruns profile buffer.
    if (tag_size < 4) return;
    if (tag_end > size) return;

    // Keep the first HAGC or CICP tag.
    const uint32_t kSig_HAGC = 0x48414743;
    const uint32_t kSig_cicp = 0x63696370;
    if (tag_sig == kSig_cicp && !cicp_tag) cicp_tag = entry;
    if (tag_sig == kSig_HAGC && !hagc_tag) hagc_tag = entry;
  }

  // Populate the CICP tag.
  if (cicp_tag) {
    uint32_t tag_offset = be32(cicp_tag + 4);
    uint32_t tag_size   = be32(cicp_tag + 8);
    uint32_t tag_type   = be32(buf + tag_offset);

    // If the tag is 'cicp' type, point at the 4 bytes after type + reserved.
    const uint32_t kType_cicp = 0x63696370;
    if (tag_type == kType_cicp && tag_size >= 12) {
      *cicp      = buf + tag_offset + 8;
      *cicp_size = 4;
    }
  }

  // Populate the HAGC tag.
  if (hagc_tag) {
    uint32_t tag_offset = be32(hagc_tag + 4);
    uint32_t tag_size   = be32(hagc_tag + 8);
    uint32_t tag_type   = be32(buf + tag_offset);

    // If the tag is 'hagc' type and the payload fits, point at the payload
    // after type + reserved + payload size.
    const uint32_t kType_hagc = 0x68616763;
    if (tag_type == kType_hagc && tag_size >= 12) {
      uint32_t payload_size = be32(buf + tag_offset + 8);
      if (payload_size <= tag_size - 12) {
        *hagc      = buf + tag_offset + 12;
        *hagc_size = payload_size;
      }
    }
  }
}

static void print_hex(const char* name, const uint8_t* data, size_t size) {
  printf("%s (%zu bytes):", name, size);
  for (size_t i = 0; i < size; i++)
    printf("%s0x%02x%s", i % 16 ? " " : "\n  ", data[i], i + 1 < size ? "," : "");
  printf("\n");
}

int main(int argc, char** argv) {
  static uint8_t buf[1 << 24];
  FILE* f = argc > 1 ? fopen(argv[1], "rb") : NULL;
  if (!f) return fprintf(stderr, "usage: %s profile.icc\n", argv[0]), 1;
  size_t len = fread(buf, 1, sizeof(buf), f);
  fclose(f);

  const uint8_t *hagc = NULL, *cicp = NULL;
  size_t hagc_size = 0, cicp_size = 0;
  icc_find_hagc_cicp(buf, len, &hagc, &hagc_size, &cicp, &cicp_size);
  print_hex("CICP", cicp, cicp_size);
  print_hex("ST 2094-50", hagc, hagc_size);
  return 0;
}
