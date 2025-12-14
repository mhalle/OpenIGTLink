/*=========================================================================

  Program:   OpenIGTLink Library -- Security Test Data
  Language:  C++

  Copyright (c) Insight Software Consortium. All rights reserved.

  This software is distributed WITHOUT ANY WARRANTY; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

/*
 * This file contains malformed/crafted byte arrays for security testing.
 * These are designed to trigger bounds checking, overflow detection,
 * and other security validation code paths.
 */

#ifndef __IGTL_TEST_DATA_SECURITY_H
#define __IGTL_TEST_DATA_SECURITY_H

#include "igtl_header.h"
#include "igtl_bind.h"
#include "igtl_polydata.h"
#include "igtl_image.h"
#include "igtl_command.h"

/*
 * Helper macro to create a minimal valid IGTL header
 * Parameters: version, type_name, device_name, timestamp, body_size
 */
#define IGTL_TEST_MAKE_HEADER(buf, ver, type, dev, ts, bsize) \
  do { \
    memset(buf, 0, IGTL_HEADER_SIZE); \
    igtl_uint16 v = ver; \
    if (igtl_is_little_endian()) v = BYTE_SWAP_INT16(v); \
    memcpy(buf, &v, 2); \
    strncpy((char*)(buf + 2), type, 12); \
    strncpy((char*)(buf + 14), dev, 20); \
    igtl_uint64 t = ts; \
    if (igtl_is_little_endian()) t = BYTE_SWAP_INT64(t); \
    memcpy(buf + 34, &t, 8); \
    igtl_uint64 s = bsize; \
    if (igtl_is_little_endian()) s = BYTE_SWAP_INT64(s); \
    memcpy(buf + 42, &s, 8); \
  } while(0)

/*
 * ============================================================================
 * BIND Message Test Data
 * ============================================================================
 */

/* Minimal valid BIND header - 0 child messages */
static unsigned char test_bind_zero_children_header[IGTL_HEADER_SIZE] = {
  0x00, 0x01,                                     /* Version 1 */
  0x42, 0x49, 0x4e, 0x44, 0x00, 0x00, 0x00, 0x00, /* BIND */
  0x00, 0x00, 0x00, 0x00,
  0x54, 0x65, 0x73, 0x74, 0x44, 0x65, 0x76, 0x69, /* TestDevice */
  0x63, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Timestamp */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, /* Body size = 4 (ncmessages + nametable_size) */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* CRC (ignored) */
};

/* Body for zero children: ncmessages=0, nametable_size=0 */
static unsigned char test_bind_zero_children_body[4] = {
  0x00, 0x00,  /* ncmessages = 0 */
  0x00, 0x00   /* nametable_size = 0 */
};

/* BIND header claiming more children than data provides */
static unsigned char test_bind_overflow_children_body[4] = {
  0x00, 0x10,  /* ncmessages = 16 (but only 2 bytes of nametable follow) */
  0x00, 0x00   /* nametable_size = 0 */
};

/* BIND with nametable_size that overflows buffer */
static unsigned char test_bind_overflow_nametable_body[24] = {
  0x00, 0x01,  /* ncmessages = 1 */
  0x54, 0x52, 0x41, 0x4e, 0x53, 0x46, 0x4f, 0x52, /* TRANSFORM type */
  0x4d, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, /* body size = 48 */
  0xFF, 0xFF   /* nametable_size = 65535 (overflows) */
};

/*
 * ============================================================================
 * POLYDATA Message Test Data
 * ============================================================================
 */

/* PolyData header with npoints causing integer overflow */
static unsigned char test_polydata_overflow_header[sizeof(igtl_polydata_header)];

/* Initialize at runtime due to byte order */
static void init_polydata_overflow_header(void)
{
  igtl_polydata_header* h = (igtl_polydata_header*)test_polydata_overflow_header;
  h->npoints = 0xFFFFFFFF;  /* Max uint32 - will overflow when multiplied by 12 */
  h->nvertices = 0;
  h->size_vertices = 0;
  h->nlines = 0;
  h->size_lines = 0;
  h->npolygons = 0;
  h->size_polygons = 0;
  h->ntriangle_strips = 0;
  h->size_triangle_strips = 0;
  h->nattributes = 0;
  if (igtl_is_little_endian())
    {
    h->npoints = BYTE_SWAP_INT32(h->npoints);
    }
}

/* PolyData with topology size exceeding buffer */
static unsigned char test_polydata_topology_overflow[sizeof(igtl_polydata_header)];

static void init_polydata_topology_overflow(void)
{
  igtl_polydata_header* h = (igtl_polydata_header*)test_polydata_topology_overflow;
  h->npoints = 1;
  h->nvertices = 0;
  h->size_vertices = 0xFFFFFFFF;  /* Claims massive vertices section */
  h->nlines = 0;
  h->size_lines = 0;
  h->npolygons = 0;
  h->size_polygons = 0;
  h->ntriangle_strips = 0;
  h->size_triangle_strips = 0;
  h->nattributes = 0;
  if (igtl_is_little_endian())
    {
    h->npoints = BYTE_SWAP_INT32(h->npoints);
    h->size_vertices = BYTE_SWAP_INT32(h->size_vertices);
    }
}

/*
 * ============================================================================
 * COMMAND Message Test Data
 * ============================================================================
 */

/* Command header size */
#define TEST_COMMAND_HEADER_SIZE 42  /* sizeof(igtl_command_header) */

/* Command with length field exceeding available data */
static unsigned char test_command_overflow_body[TEST_COMMAND_HEADER_SIZE + 10] = {
  /* commandId (4 bytes) */
  0x00, 0x00, 0x00, 0x01,
  /* commandName (32 bytes) - not null terminated */
  0x54, 0x65, 0x73, 0x74, 0x43, 0x6d, 0x64, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* encoding (2 bytes) */
  0x00, 0x03,
  /* length (4 bytes) - claims 0xFFFFFFFF bytes follow */
  0xFF, 0xFF, 0xFF, 0xFF,
  /* Only 10 bytes of actual command data */
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a
};

/* Command with non-null-terminated commandName */
static unsigned char test_command_no_null_name[TEST_COMMAND_HEADER_SIZE] = {
  /* commandId */
  0x00, 0x00, 0x00, 0x01,
  /* commandName - all non-null */
  0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
  0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
  0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
  0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
  /* encoding */
  0x00, 0x03,
  /* length = 0 */
  0x00, 0x00, 0x00, 0x00
};

/*
 * ============================================================================
 * QUERY Message Test Data
 * ============================================================================
 */

#define TEST_QUERY_HEADER_SIZE 26  /* sizeof(igtl_query_header) */

/* Query with deviceUIDLength exceeding buffer */
static unsigned char test_query_uid_overflow[TEST_QUERY_HEADER_SIZE + 4] = {
  /* queryID (4 bytes) */
  0x00, 0x00, 0x00, 0x01,
  /* queryDataType (20 bytes) */
  0x49, 0x4d, 0x41, 0x47, 0x45, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  /* deviceUIDLength (2 bytes) - claims 0xFFFF bytes */
  0xFF, 0xFF,
  /* Only 4 bytes of UID data */
  0x41, 0x42, 0x43, 0x44
};

/*
 * ============================================================================
 * IMAGE Message Test Data
 * ============================================================================
 */

/* Image header size */
#define TEST_IMAGE_HEADER_SIZE 72  /* IGTL_IMAGE_HEADER_SIZE */

/* Minimal valid image header for testing (72 bytes total)
 * Structure: header_version(2) + num_components(1) + scalar_type(1) +
 *            endian(1) + coord(1) + size[3](6) + matrix[12](48) +
 *            subvol_offset[3](6) + subvol_size[3](6) = 72 bytes */
static unsigned char test_image_minimal_header[TEST_IMAGE_HEADER_SIZE] = {
  /* header_version (2) + num_components (1) + scalar_type (1) = 4 bytes */
  0x00, 0x01, 0x01, 0x03,
  /* endian (1) + coord (1) + size[3] (6) = 8 bytes */
  0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
  /* matrix[12] = 48 bytes - identity-ish */
  0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x80, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* subvol_offset[3] (6) + subvol_size[3] (6) = 12 bytes */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01
};

/*
 * ============================================================================
 * VIDEO Message Test Data
 * ============================================================================
 */

#define TEST_VIDEO_HEADER_SIZE 80  /* IGTL_VIDEO_HEADER_SIZE */
#define TEST_STT_VIDEO_SIZE 12     /* IGTL_STT_VIDEO_SIZE */

/* StartVideo body smaller than required */
static unsigned char test_stt_video_truncated[4] = {
  0x00, 0x00, 0x00, 0x01  /* Only 4 bytes, needs 12 */
};

/* Video message body smaller than header */
static unsigned char test_video_truncated[40];  /* Only 40 bytes, needs 80 */

/*
 * ============================================================================
 * Element-based Messages (ImageMeta, LabelMeta, Point, etc.)
 * ============================================================================
 */

/* ImageMeta element size */
#define TEST_IMAGEMETA_ELEMENT_SIZE 260

/* Body with size not divisible by element size */
static unsigned char test_imagemeta_partial_element[100];  /* Not divisible by 260 */

/* Point element size */
#define TEST_POINT_ELEMENT_SIZE 136

/* Body with partial point element */
static unsigned char test_point_partial_element[100];  /* Not divisible by 136 */

/*
 * ============================================================================
 * RTS (Response) Messages
 * ============================================================================
 */

/* RTSBind with empty body (needs at least 1 byte for status) */
static unsigned char test_rtsbind_empty_body[1];  /* Will test with size=0 */

/*
 * ============================================================================
 * Metadata Test Data (Extended Header V2)
 * ============================================================================
 */

/* Extended header with sizes exceeding body */
static unsigned char test_extended_header_overflow[12] = {
  0x00, 0x0C,              /* extended_header_size = 12 (minimum) */
  0x00, 0x00, 0x00, 0x01,  /* message_id = 1 */
  0xFF, 0xFF,              /* meta_data_header_size = 65535 (overflow) */
  0xFF, 0xFF, 0xFF, 0xFF   /* meta_data_size = 4GB (overflow) */
};

/* Metadata header with index_count exceeding header size */
static unsigned char test_metadata_index_overflow[6] = {
  0x00, 0x64,  /* index_count = 100 entries (but only 4 more bytes available) */
  0x00, 0x00, 0x00, 0x00
};

/*
 * ============================================================================
 * String Safety Test Data
 * ============================================================================
 */

/* Maximum length + 1 string for boundary testing */
#define TEST_MAX_NAME_LEN 22  /* IGTL_HEADER_NAME_SIZE + 1 + null */
static char test_overlong_device_name[TEST_MAX_NAME_LEN] =
  "AAAAAAAAAAAAAAAAAAAAA";  /* 21 A's + null = 22 bytes, max name is 20 */

#define TEST_MAX_TYPE_LEN 14  /* IGTL_HEADER_TYPE_SIZE + 1 + null */
static char test_overlong_type_name[TEST_MAX_TYPE_LEN] =
  "AAAAAAAAAAAAA";  /* 13 A's + null = 14 bytes, max type is 12 */

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/* Initialize all test data that requires runtime byte-order handling */
static void igtl_test_security_init(void)
{
  init_polydata_overflow_header();
  init_polydata_topology_overflow();
  memset(test_video_truncated, 0, sizeof(test_video_truncated));
  memset(test_imagemeta_partial_element, 0x41, sizeof(test_imagemeta_partial_element));
  memset(test_point_partial_element, 0x42, sizeof(test_point_partial_element));
}

#endif /* __IGTL_TEST_DATA_SECURITY_H */
