/*
 * main.c -- BUN file parser: entry point and human-readable output.
 *
 * Responsibilities of this file:
 *   - Argument validation and error reporting.
 *   - Calling the parse API (bun_parse.c) in the correct order.
 *   - Printing a human-readable summary to stdout on BUN_OK.
 *   - Printing violation messages to stderr on BUN_MALFORMED / BUN_UNSUPPORTED.
 *   - Reading a small payload preview for each asset for display purposes.
 *
 * Output format is documented in Section 1 of the project report.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <limits.h>
 
 #include "bun.h"
 
 /* -------------------------------------------------------------------------
  * Display constants
  * ------------------------------------------------------------------------- */
 
 /* Maximum bytes of payload data shown per asset (2 lines of 16). */
 #define PREVIEW_BYTES_MAX  32u
 
 /* Bytes shown per line in the hex+ASCII display (matches xxd default). */
 #define PREVIEW_LINE_WIDTH 16u
 
 /* Maximum characters of an asset name shown before truncation. */
 #define NAME_DISPLAY_MAX   60u
 
 /* Buffer size for the decoded flags string. */
 #define FLAGS_BUF_SIZE     128u
 
 /* Column width for the label prefix in the header and asset blocks.
  * All field labels are padded to this width so values align vertically. */
 #define LABEL_COL          22
 
 /* Label prefix for the first payload line and continuation lines. */
 #define PAYLOAD_LABEL      "    Payload:          "
 #define PAYLOAD_CONT       "                      "
 
 /* -------------------------------------------------------------------------
  * Helper: compression label
  * ------------------------------------------------------------------------- */
 
 /*
  * Returns a human-readable label for a compression value.
  * Unknown values return "unknown"; the parser should have already returned
  * BUN_UNSUPPORTED for those, so this is a fallback only.
  */
 static const char *compression_label(u32 comp) {
     switch (comp) {
         case 0:  return "none";
         case 1:  return "RLE";
         case 2:  return "zlib";
         default: return "unknown";
     }
 }
 
 /* -------------------------------------------------------------------------
  * Helper: flag field decoder
  * ------------------------------------------------------------------------- */
 
 /*
  * Decodes the flags field into a human-readable comma-separated string.
  * Known flag bits are expanded to their named constants. Any unknown bits
  * are appended as UNKNOWN(0xNN). If no bits are set, writes "none".
  *
  * buf must be at least FLAGS_BUF_SIZE bytes.
  */
 static void decode_flags(u32 flags, char *buf, size_t bufsize) {
     if (bufsize == 0) return;
 
     if (flags == 0) {
         snprintf(buf, bufsize, "none");
         return;
     }
 
     buf[0] = '\0';
     size_t pos = 0;
     int first = 1;
     int n;
 
     if (flags & BUN_FLAG_ENCRYPTED) {
         n = snprintf(buf + pos, bufsize - pos, "BUN_FLAG_ENCRYPTED");
         if (n > 0 && (size_t)n < bufsize - pos) pos += (size_t)n;
         first = 0;
     }
     if (flags & BUN_FLAG_EXECUTABLE) {
         n = snprintf(buf + pos, bufsize - pos,
                      "%sBUN_FLAG_EXECUTABLE", first ? "" : ", ");
         if (n > 0 && (size_t)n < bufsize - pos) pos += (size_t)n;
         first = 0;
     }
 
     /* Report any bits outside the two known flags. */
     u32 known = BUN_FLAG_ENCRYPTED | BUN_FLAG_EXECUTABLE;
     if (flags & ~known) {
         snprintf(buf + pos, bufsize - pos,
                  "%sUNKNOWN(0x%X)", first ? "" : ", ", flags & ~known);
     }
 }
 
 /* -------------------------------------------------------------------------
  * Helper: hex+ASCII payload preview
  * ------------------------------------------------------------------------- */
 
 /*
  * Prints a hex+ASCII dual-view preview of payload data, matching the
  * output style of hexdump -C and xxd. Each line shows PREVIEW_LINE_WIDTH
  * bytes of hex followed by an ASCII gutter. Non-printable bytes (outside
  * the range 0x20 to 0x7E) are rendered as '.'.
  *
  * Parameters:
  *   data         - the bytes to display (up to PREVIEW_BYTES_MAX).
  *   preview_len  - how many bytes are in data[].
  *   total_size   - the full data_size from the asset record, used to
  *                  decide whether to print a truncation indicator.
  */
 static void print_hex_ascii_preview(const u8 *data,
                                     size_t preview_len,
                                     u64 total_size) {
     if (total_size == 0) {
         printf("%s(empty)\n", PAYLOAD_LABEL);
         return;
     }
 
     int truncated = (total_size > PREVIEW_BYTES_MAX);
 
     for (size_t offset = 0; offset < preview_len; offset += PREVIEW_LINE_WIDTH) {
         size_t line_bytes = preview_len - offset;
         if (line_bytes > PREVIEW_LINE_WIDTH) line_bytes = PREVIEW_LINE_WIDTH;
 
         /* Print label on first line, continuation padding on subsequent lines. */
         if (offset == 0) {
             printf("%s", PAYLOAD_LABEL);
         } else {
             printf("%s", PAYLOAD_CONT);
         }
 
         /* Hex section: always PREVIEW_LINE_WIDTH columns wide.
          * Partial lines are padded with spaces so the ASCII gutter aligns. */
         for (size_t i = 0; i < PREVIEW_LINE_WIDTH; i++) {
             if (i < line_bytes) {
                 printf("%02X ", data[offset + i]);
             } else {
                 printf("   ");
             }
         }
 
         /* ASCII gutter. */
         printf(" |");
         for (size_t i = 0; i < line_bytes; i++) {
             u8 b = data[offset + i];
             printf("%c", (b >= 0x20 && b <= 0x7E) ? (char)b : '.');
         }
         printf("|\n");
     }
 
     if (truncated) {
         printf("%s...\n", PAYLOAD_CONT);
     }
 }
 
 /* -------------------------------------------------------------------------
  * Helper: read asset payload preview
  * ------------------------------------------------------------------------- */
 
 /*
  * Seeks to the start of an asset's data section and reads up to bufsize
  * bytes for use in the payload preview display. Does not decompress.
  *
  * Returns the number of bytes read, or 0 on any error (seek failure,
  * read failure, zero data size). main.c treats 0 as "no preview available"
  * and prints (empty) instead.
  *
  * Note on large offsets: on the CITS3007 standard development environment
  * (64-bit Linux), long is 64 bits, so fseek handles the full file range.
  */
 static size_t read_asset_preview(BunParseContext *ctx,
                                  const BunHeader *header,
                                  const BunAssetRecord *r,
                                  u8 *buf, size_t bufsize) {
     if (r->data_size == 0 || bufsize == 0) return 0;
 
     /* Compute actual file offset: data_section_offset + data_offset.
      * Guard against u64 overflow before converting to long. */
     if (r->data_offset > (u64)LONG_MAX - header->data_section_offset) return 0;
     u64 abs_offset = header->data_section_offset + r->data_offset;
     if (abs_offset > (u64)LONG_MAX) return 0;
 
     if (fseek(ctx->file, (long)abs_offset, SEEK_SET) != 0) return 0;
 
     size_t to_read = bufsize;
     if ((u64)to_read > r->data_size) {
         to_read = (size_t)r->data_size;
     }
 
     return fread(buf, 1u, to_read, ctx->file);
 }
 
 /* -------------------------------------------------------------------------
  * Print: BUN file header
  * ------------------------------------------------------------------------- */
 
 /*
  * Prints all BUN header fields to stdout in labelled key-value format.
  * Offsets and sizes are shown in both hex and decimal.
  */
 static void print_header(const BunHeader *h) {
     printf("=== BUN HEADER ===\n");
     printf("Magic:                0x%08X (\"BUN0\")\n", h->magic);
     printf("Version:              %u.%u\n",
            (unsigned)h->version_major, (unsigned)h->version_minor);
     printf("Asset Count:          %u\n", (unsigned)h->asset_count);
     printf("Asset Table Offset:   0x%016llX (%llu)\n",
            (unsigned long long)h->asset_table_offset,
            (unsigned long long)h->asset_table_offset);
     printf("String Table Offset:  0x%016llX (%llu)\n",
            (unsigned long long)h->string_table_offset,
            (unsigned long long)h->string_table_offset);
     printf("String Table Size:    %llu bytes\n",
            (unsigned long long)h->string_table_size);
     printf("Data Section Offset:  0x%016llX (%llu)\n",
            (unsigned long long)h->data_section_offset,
            (unsigned long long)h->data_section_offset);
     printf("Data Section Size:    %llu bytes\n",
            (unsigned long long)h->data_section_size);
     printf("Reserved:             0x%016llX\n",
            (unsigned long long)h->reserved);
 }
 
 /* -------------------------------------------------------------------------
  * Print: single asset record
  * ------------------------------------------------------------------------- */
 
 /*
  * Prints one asset record to stdout. name is a null-terminated string
  * copied from the string table by bun_parse_assets(). preview/preview_len
  * are the raw bytes read for display; r->data_size is the total payload
  * size (used to decide whether to show the truncation indicator).
  */
 static void print_asset(u32 index,
                          const BunAssetRecord *r,
                          const char *name,
                          const u8 *preview,
                          size_t preview_len) {
     /* Asset name header line with truncation if needed. */
     printf("\n[%u] ", (unsigned)index);
     if (r->name_length > NAME_DISPLAY_MAX) {
         printf("%.*s ...\n", (int)NAME_DISPLAY_MAX, name);
     } else {
         printf("%s\n", name);
     }
 
     /* Flags and checksum label. */
     char flags_buf[FLAGS_BUF_SIZE];
     decode_flags(r->flags, flags_buf, sizeof(flags_buf));
 
     const char *cksum_note = (r->checksum == 0) ? " (unused)" : "";
 
     printf("    Type:             %u\n", (unsigned)r->type);
     printf("    Compression:      %u (%s)\n",
            (unsigned)r->compression, compression_label(r->compression));
     printf("    Data Offset:      0x%016llX (%llu)\n",
            (unsigned long long)r->data_offset,
            (unsigned long long)r->data_offset);
     printf("    Data Size:        %llu bytes\n",
            (unsigned long long)r->data_size);
     printf("    Uncompressed:     %llu bytes\n",
            (unsigned long long)r->uncompressed_size);
     printf("    Checksum:         0x%08X%s\n",
            (unsigned)r->checksum, cksum_note);
     printf("    Flags:            %s\n", flags_buf);
 
     print_hex_ascii_preview(preview, preview_len, r->data_size);
 }
 
 /* -------------------------------------------------------------------------
  * Print: violation list
  * ------------------------------------------------------------------------- */
 
 /*
  * Prints all recorded spec violations to stderr, one per line, in the
  * format:  VIOLATION: <message>
  *
  * If no violations were recorded (e.g. because the parse functions did not
  * yet populate them), prints a generic fallback message instead.
  */
 static void print_violations(const BunParseContext *ctx) {
     if (ctx->violation_count == 0) {
         fprintf(stderr, "VIOLATION: file is invalid or uses unsupported features "
                         "(no further detail available)\n");
         return;
     }
     for (int i = 0; i < ctx->violation_count; i++) {
         fprintf(stderr, "VIOLATION: %s\n", ctx->violations[i]);
     }
 }
 
 /* -------------------------------------------------------------------------
  * Entry point
  * ------------------------------------------------------------------------- */
 
 int main(int argc, char *argv[]) {
 
     /* Validate argument count before touching any file. */
     if (argc != 2) {
         fprintf(stderr, "Usage: %s <file.bun>\n", argv[0]);
         return BUN_ERR_ARGS;
     }
 
     const char *path = argv[1];
     BunParseContext ctx    = {0};
     BunHeader       header = {0};
 
     /* Open the file and determine its size. */
     bun_result_t result = bun_open(path, &ctx);
     if (result != BUN_OK) {
         fprintf(stderr, "Error: could not open '%s'\n", path);
         return result;
     }
 
     /* Parse and validate the header. */
     result = bun_parse_header(&ctx, &header);
     if (result != BUN_OK) {
         print_violations(&ctx);
         bun_close(&ctx);
         return result;
     }
 
     /* Print the header -- always shown when the header is valid. */
     print_header(&header);
 
     /* Parse and validate all asset records. bun_parse_assets() populates
      * ctx.assets, ctx.asset_names, and ctx.asset_count. On BUN_MALFORMED
      * or BUN_UNSUPPORTED it may have partially filled these (up to the
      * first bad record), which is fine -- we print what we have. */
     result = bun_parse_assets(&ctx, &header);
 
     /* Print however many assets were successfully parsed. */
     printf("\n=== ASSETS (%u total) ===\n", (unsigned)header.asset_count);
 
     for (u32 i = 0; i < ctx.asset_count; i++) {
         u8 preview[PREVIEW_BYTES_MAX];
         size_t preview_len = read_asset_preview(&ctx, &header,
                                                 &ctx.assets[i],
                                                 preview, sizeof(preview));
         print_asset(i, &ctx.assets[i], ctx.asset_names[i],
                     preview, preview_len);
     }
 
     /* On error, print violations to stderr after the stdout output. */
     if (result != BUN_OK) {
         print_violations(&ctx);
     }
 
     bun_close(&ctx);
     return result;
 }
 
