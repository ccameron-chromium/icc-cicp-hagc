#include <stdint.h>
#include <stdio.h>

// Reads a big-endian (ICC byte order) uint32 from p.
static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

// Finds the ST 2094-50 payload of the 'HAGC' tag and the 4 bytes of 'cicp' tag
// data in the ICC profile in buf[0..len). Writes {offset, size} (relative to
// buf) to hagc and cicp, or {0, 0} if absent. Returns 0 if the profile fails
// basic validation or a tag is malformed (the same checks as skcms).
int icc_find_hagc_cicp(const uint8_t* buf, size_t len, uint32_t hagc[2], uint32_t cicp[2]) {
  const uint32_t kHeaderSize   = 128;         // ICC header size.
  const uint32_t kTagEntrySize = 12;          // Tag table entry: signature, offset, size.
  const uint32_t kSig_acsp     = 0x61637370;  // 'acsp' profile file signature.
  const uint32_t kSig_HAGC     = 0x48414743;  // 'HAGC' tag signature.
  const uint32_t kSig_cicp     = 0x63696370;  // 'cicp' tag signature.
  const uint32_t kType_hagc    = 0x68616763;  // 'hagc' tag type.
  const uint32_t kType_cicp    = 0x63696370;  // 'cicp' tag type.

  hagc[0] = hagc[1] = cicp[0] = cicp[1] = 0;
  if (len < kHeaderSize + 4) return 0;                      // Header + tag count must fit.

  uint64_t size       = be32(buf);                          // Declared profile size.
  uint8_t  version    = buf[8];                             // Major version.
  uint32_t signature  = be32(buf + 36);                     // Must be 'acsp'.
  uint64_t tag_count  = be32(buf + kHeaderSize);
  uint64_t tags_end   = kHeaderSize + 4 + kTagEntrySize * tag_count;

  if (signature != kSig_acsp) return 0;                     // Not an ICC profile.
  if (size > len) return 0;                                 // Profile overruns buffer.
  if (size < tags_end) return 0;                            // Tag table overruns profile.
  if (version > 4) return 0;                                // Unknown major version.

  const uint8_t* cicp_tag = NULL;                           // Tag table entries.
  const uint8_t* hagc_tag = NULL;
  for (uint64_t i = 0; i < tag_count; i++) {
    const uint8_t* entry = buf + kHeaderSize + 4 + kTagEntrySize * i;
    uint32_t tag_sig    = be32(entry);
    uint32_t tag_offset = be32(entry + 4);
    uint32_t tag_size   = be32(entry + 8);
    uint64_t tag_end    = (uint64_t)tag_offset + tag_size;
    if (tag_size < 4) return 0;                             // Too small to hold a type.
    if (tag_end > size) return 0;                           // Tag overruns profile.

    if (tag_sig == kSig_cicp && !cicp_tag) cicp_tag = entry;  // Keep the first match.
    if (tag_sig == kSig_HAGC && !hagc_tag) hagc_tag = entry;
  }

  if (cicp_tag) {                                           // Same as skcms read_cicp().
    uint32_t tag_offset = be32(cicp_tag + 4);
    uint32_t tag_size   = be32(cicp_tag + 8);
    uint32_t tag_type   = be32(buf + tag_offset);
    if (tag_type != kType_cicp) return 0;                   // Wrong tag type.
    if (tag_size < 12) return 0;                            // Type + reserved + 4 bytes.
    cicp[0] = tag_offset + 8;                               // Skip type + reserved.
    cicp[1] = 4;                                            // Primaries, transfer, matrix, range.
  }

  if (hagc_tag) {                                           // Same as skcms read_hagc().
    uint32_t tag_offset   = be32(hagc_tag + 4);
    uint32_t tag_size     = be32(hagc_tag + 8);
    uint32_t tag_type     = be32(buf + tag_offset);
    if (tag_type != kType_hagc) return 0;                   // Wrong tag type.
    if (tag_size < 12) return 0;                            // Type + reserved + size.
    uint32_t payload_size = be32(buf + tag_offset + 8);
    if (payload_size > tag_size - 12) return 0;             // Payload overruns tag.
    hagc[0] = tag_offset + 12;                              // Skip type + reserved + size.
    hagc[1] = payload_size;
  }
  return 1;
}

static void print_hex(const char* name, const uint8_t* data, uint32_t size) {
  printf("%s (%u bytes):", name, size);
  for (uint32_t i = 0; i < size; i++)
    printf("%s0x%02x%s", i % 16 ? " " : "\n  ", data[i], i + 1 < size ? "," : "");
  printf("\n");
}

int main(int argc, char** argv) {
  static uint8_t buf[1 << 24];
  FILE* f = argc > 1 ? fopen(argv[1], "rb") : NULL;
  if (!f) return fprintf(stderr, "usage: %s profile.icc\n", argv[0]), 1;
  size_t len = fread(buf, 1, sizeof(buf), f);
  fclose(f);

  uint32_t hagc[2], cicp[2];
  if (!icc_find_hagc_cicp(buf, len, hagc, cicp)) return fprintf(stderr, "invalid ICC profile\n"), 1;
  print_hex("CICP", buf + cicp[0], cicp[1]);
  print_hex("ST 2094-50", buf + hagc[0], hagc[1]);
  return 0;
}
