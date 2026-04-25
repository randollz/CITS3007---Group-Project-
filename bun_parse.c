#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bun.h"

/**
 * Example helper: convert 4 bytes in `buf`, positioned at `offset`,
 * into a little-endian u32.
 */
static u32 read_u32_le(const u8 *buf, size_t offset) {
  return (u32)buf[offset]
     | (u32)buf[offset + 1] << 8
     | (u32)buf[offset + 2] << 16
     | (u32)buf[offset + 3] << 24;

}

static u16 read_u16_le(const u8 *buf, size_t offset) {
  return (u16)buf[offset]
     | (u16)buf[offset + 1] << 8;
}

static u64 read_u64_le(const u8 *buf, size_t offset) {
  return (u64)buf[offset]
     | (u64)buf[offset + 1] << 8
     | (u64)buf[offset + 2] << 16
     | (u64)buf[offset + 3] << 24
     | (u64)buf[offset + 4] << 32
     | (u64)buf[offset + 5] << 40
     | (u64)buf[offset + 6] << 48
     | (u64)buf[offset + 7] << 56;
}

//
// API implementation
//

bun_result_t bun_open(const char *path, BunParseContext *ctx) {
  // we open the file; seek to the end, to get the size; then jump back to the
  // beginning, ready to start parsing.

  ctx->file = fopen(path, "rb");
  if (!ctx->file) {
    return BUN_ERR_IO;
  }

  if (fseek(ctx->file, 0, SEEK_END) != 0) {
    fclose(ctx->file);
    return BUN_ERR_IO;
  }
  ctx->file_size = ftell(ctx->file);
  if (ctx->file_size < 0) {
    fclose(ctx->file);
    return BUN_ERR_IO;
  }
  rewind(ctx->file);

  return BUN_OK;
}

bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header) {
  u8 buf[BUN_HEADER_SIZE];

  // our file is far too short, and cannot be valid!
  // (query: how do we let `main` know that "file was too short"
  // was the exact problem? Where can we put details about the
  // exact validation problem that occurred?)
  if (ctx->file_size < (long)BUN_HEADER_SIZE) {
    return BUN_MALFORMED;
  }

  // slurp the header into `buf`
  if (fread(buf, 1, BUN_HEADER_SIZE, ctx->file) != BUN_HEADER_SIZE) {
    return BUN_ERR_IO;
  }

  // TODO: populate `header` from `buf`.
  header->magic = read_u32_le(buf, 0);
  header->version_major = read_u16_le(buf, 4);
  header->version_minor = read_u16_le(buf, 6);
  header->asset_count = read_u32_le(buf, 8);
  header->asset_table_offset = read_u64_le(buf, 12);
  header->string_table_offset = read_u64_le(buf, 20);
  header->string_table_size = read_u64_le(buf, 28);
  header->data_section_offset = read_u64_le(buf, 36);
  header->data_section_size = read_u64_le(buf, 44);
  header->reserved = read_u64_le(buf, 52);

  // TODO: validate fields and return BUN_MALFORMED or BUN_UNSUPPORTED
  // as required by the spec. The magic check is a good place to start.

  if (header->magic != BUN_MAGIC) {
    return BUN_MALFORMED;
  }

  if (header->version_major != BUN_VERSION_MAJOR || header->version_minor != BUN_VERSION_MINOR) {
    return BUN_UNSUPPORTED;
  }

  if (header->asset_table_offset % 4 != 0 || header->string_table_offset % 4 != 0 || header->string_table_size % 4 != 0 || header->data_section_offset % 4 != 0 || header->data_section_size % 4 != 0) {
    return BUN_MALFORMED;
  }

  u64 file_size = (u64)ctx->file_size;
  u64 asset_table_end = header->asset_table_offset + (u64)header->asset_count * BUN_ASSET_RECORD_SIZE;
  u64 string_table_end = header->string_table_offset + header->string_table_size;
  u64 data_section_end = header->data_section_offset + header->data_section_size;

  if (asset_table_end > file_size ||
      string_table_end > file_size ||
      data_section_end > file_size) {
    return BUN_MALFORMED;
  }

  if (asset_table_end > header->string_table_offset &&
      header->asset_table_offset < string_table_end) {
    return BUN_MALFORMED;
  }

  if (string_table_end > header->data_section_offset &&
      header->string_table_offset < data_section_end) {
    return BUN_MALFORMED;
  }

  return BUN_OK;
}

/* Issue #12 — validate that an asset's name is non-empty and every byte is
 * in the printable ASCII range 0x20–0x7E. Returns BUN_MALFORMED on violation. */
static bun_result_t validate_asset_name(BunParseContext *ctx, u32 idx,
                                        const u8 *strtab, u64 strtab_size,
                                        u32 name_offset, u32 name_length) {
  if (name_length == 0) {
    if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
      snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
               "asset %u: name_length is 0", (unsigned)idx);
      ctx->violation_count++;
    }
    return BUN_MALFORMED;
  }

  if ((u64)name_offset + name_length > strtab_size) {
    if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
      snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
               "asset %u: name extends beyond string table", (unsigned)idx);
      ctx->violation_count++;
    }
    return BUN_MALFORMED;
  }

  for (u32 j = 0; j < name_length; j++) {
    u8 b = strtab[name_offset + j];
    if (b < 0x20 || b > 0x7E) {
      if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
        snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
                 "asset %u: name byte at offset %u is non-printable (0x%02X)",
                 (unsigned)idx, (unsigned)j, (unsigned)b);
        ctx->violation_count++;
      }
      return BUN_MALFORMED;
    }
  }

  return BUN_OK;
}

/* Issue #13 — validate the compression field and related size constraints.
 * compression=0: uncompressed_size must be 0.
 * compression=1 (RLE): data_size must be even.
 * compression=2 (zlib) or unknown: not supported. */
static bun_result_t validate_asset_compression(BunParseContext *ctx, u32 idx,
                                               u32 compression, u64 data_size,
                                               u64 uncompressed_size) {
  if (compression == 0) {
    if (uncompressed_size != 0) {
      if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
        snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
                 "asset %u: compression=0 (none) but uncompressed_size is non-zero",
                 (unsigned)idx);
        ctx->violation_count++;
      }
      return BUN_MALFORMED;
    }
    return BUN_OK;
  }

  if (compression == 1) {
    if (data_size % 2 != 0) {
      if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
        snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
                 "asset %u: RLE compression requires even data_size, got %llu",
                 (unsigned)idx, (unsigned long long)data_size);
        ctx->violation_count++;
      }
      return BUN_MALFORMED;
    }
    return BUN_OK;
  }

  if (compression == 2) {
    if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
      snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
               "asset %u: zlib compression (compression=2) is not supported",
               (unsigned)idx);
      ctx->violation_count++;
    }
    return BUN_UNSUPPORTED;
  }

  if (ctx->violation_count < BUN_MAX_VIOLATIONS) {
    snprintf(ctx->violations[ctx->violation_count], BUN_VIOLATION_MSG_LEN,
             "asset %u: unknown compression value %u",
             (unsigned)idx, (unsigned)compression);
    ctx->violation_count++;
  }
  return BUN_UNSUPPORTED;
}

bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {
  if (header->asset_count == 0)
    return BUN_OK;

  bun_result_t result = BUN_OK;

  ctx->assets = calloc(header->asset_count, sizeof(BunAssetRecord));
  if (!ctx->assets)
    return BUN_ERR_IO;

  ctx->asset_names = calloc(header->asset_count, sizeof(char *));
  if (!ctx->asset_names) {
    free(ctx->assets);
    ctx->assets = NULL;
    return BUN_ERR_IO;
  }

  /* Load the full string table into a heap buffer for name reads. */
  u8 *strtab = NULL;
  if (header->string_table_size > 0) {
    strtab = malloc((size_t)header->string_table_size);
    if (!strtab) {
      free(ctx->asset_names);
      free(ctx->assets);
      ctx->assets = NULL;
      ctx->asset_names = NULL;
      return BUN_ERR_IO;
    }
    if (fseek(ctx->file, (long)header->string_table_offset, SEEK_SET) != 0 ||
        fread(strtab, 1, (size_t)header->string_table_size, ctx->file) !=
            (size_t)header->string_table_size) {
      free(strtab);
      free(ctx->asset_names);
      free(ctx->assets);
      ctx->assets = NULL;
      ctx->asset_names = NULL;
      return BUN_ERR_IO;
    }
  }

  if (fseek(ctx->file, (long)header->asset_table_offset, SEEK_SET) != 0) {
    free(strtab);
    free(ctx->asset_names);
    free(ctx->assets);
    ctx->assets = NULL;
    ctx->asset_names = NULL;
    return BUN_ERR_IO;
  }

  for (u32 i = 0; i < header->asset_count; i++) {
    u8 rec_buf[BUN_ASSET_RECORD_SIZE];
    if (fread(rec_buf, 1, BUN_ASSET_RECORD_SIZE, ctx->file) != BUN_ASSET_RECORD_SIZE) {
      free(strtab);
      return BUN_ERR_IO;
    }

    /* Populate asset record from the on-disk buffer using little-endian helpers.
     * Field byte offsets match the BunAssetRecord layout in bun.h and
     * the _RECORD_FMT in bunfile_generator.py. */
    BunAssetRecord *r = &ctx->assets[i];
    r->name_offset       = read_u32_le(rec_buf, 0);
    r->name_length       = read_u32_le(rec_buf, 4);
    r->data_offset       = read_u64_le(rec_buf, 8);
    r->data_size         = read_u64_le(rec_buf, 16);
    r->uncompressed_size = read_u64_le(rec_buf, 24);
    r->compression       = read_u32_le(rec_buf, 32);
    r->type              = read_u32_le(rec_buf, 36);
    r->checksum          = read_u32_le(rec_buf, 40);
    r->flags             = read_u32_le(rec_buf, 44);

    /* Copy name as a null-terminated string; clamp to string table bounds so
     * the memcpy is safe even if validation later reports a violation. */
    u64 name_end = (u64)r->name_offset + r->name_length;
    u32 copy_len = (name_end <= header->string_table_size)
                   ? r->name_length
                   : (header->string_table_size > r->name_offset
                      ? (u32)(header->string_table_size - r->name_offset)
                      : 0u);
    ctx->asset_names[i] = malloc(copy_len + 1);
    if (!ctx->asset_names[i]) {
      free(strtab);
      return BUN_ERR_IO;
    }
    if (copy_len > 0 && strtab != NULL)
      memcpy(ctx->asset_names[i], strtab + r->name_offset, copy_len);
    ctx->asset_names[i][copy_len] = '\0';
    ctx->asset_count++;

    /* Issue #12 — validate asset name bytes. */
    bun_result_t vr = validate_asset_name(ctx, i, strtab,
                                          header->string_table_size,
                                          r->name_offset, r->name_length);
    if (vr != BUN_OK && result == BUN_OK)
      result = vr;

    /* Issue #13 — validate compression field and size constraints. */
    vr = validate_asset_compression(ctx, i,
                                    r->compression, r->data_size,
                                    r->uncompressed_size);
    if (vr != BUN_OK && result == BUN_OK)
      result = vr;
  }

  free(strtab);
  return result;
}

bun_result_t bun_close(BunParseContext *ctx) {
  assert(ctx->file);

  /* Free heap allocations made by bun_parse_assets(). */
  if (ctx->assets) {
    for (u32 i = 0; i < ctx->asset_count; i++)
      free(ctx->asset_names[i]);
    free(ctx->asset_names);
    free(ctx->assets);
    ctx->assets = NULL;
    ctx->asset_names = NULL;
  }

  int res = fclose(ctx->file);
  if (res) {
    return BUN_ERR_IO;
  } else {
    ctx->file = NULL;
    return BUN_OK;
  }
}
