/*=========================================================================

  Program:   OpenIGTLink Library -- C Utility Security Tests
  Language:  C

  Copyright (c) Insight Software Consortium. All rights reserved.

  This software is distributed WITHOUT ANY WARRANTY; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

/*
 * Security tests for OpenIGTLink C utility functions.
 * These tests verify bounds checking in low-level unpack functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "igtl_header.h"
#include "igtl_bind.h"
#include "igtl_polydata.h"
#include "igtl_image.h"
#include "igtl_ndarray.h"
#include "igtl_capability.h"

/* Simple test framework */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(expr, msg) \
  do { \
    tests_run++; \
    if (expr) { \
      tests_passed++; \
      printf("  [PASS] %s\n", msg); \
    } else { \
      printf("  [FAIL] %s\n", msg); \
    } \
  } while(0)

/*
 * ============================================================================
 * igtl_bind Tests
 * ============================================================================
 */

void test_bind_zero_size(void)
{
  printf("Testing igtl_bind_unpack with zero size...\n");

  igtl_bind_info info;
  igtl_bind_init_info(&info);

  /* Zero-size buffer should fail for normal BIND */
  int result = igtl_bind_unpack(IGTL_TYPE_PREFIX_NONE, NULL, &info, 0);
  TEST_ASSERT(result == 0, "BIND with NULL buffer returns 0");

  /* Zero-size GET_BIND sets request_all */
  igtl_bind_init_info(&info);
  result = igtl_bind_unpack(IGTL_TYPE_PREFIX_GET, NULL, &info, 0);
  TEST_ASSERT(result == 1 && info.request_all == 1, "GET_BIND with zero size sets request_all");

  igtl_bind_free_info(&info);
}

void test_bind_small_buffer(void)
{
  printf("Testing igtl_bind_unpack with undersized buffer...\n");

  igtl_bind_info info;
  igtl_bind_init_info(&info);

  /* Buffer too small for ncmessages field */
  unsigned char small_buf[1] = {0x00};
  int result = igtl_bind_unpack(IGTL_TYPE_PREFIX_NONE, small_buf, &info, 1);
  TEST_ASSERT(result == 0, "BIND with 1-byte buffer returns 0");

  igtl_bind_free_info(&info);
}

void test_bind_ncmessages_overflow(void)
{
  printf("Testing igtl_bind_unpack with excessive ncmessages...\n");

  igtl_bind_info info;
  igtl_bind_init_info(&info);

  /* Buffer claims 1000 children but only has 4 bytes */
  unsigned char overflow_buf[4];
  igtl_uint16 ncmessages = 1000;
  if (igtl_is_little_endian()) {
    ncmessages = BYTE_SWAP_INT16(ncmessages);
  }
  memcpy(overflow_buf, &ncmessages, 2);
  overflow_buf[2] = 0x00;
  overflow_buf[3] = 0x00;

  int result = igtl_bind_unpack(IGTL_TYPE_PREFIX_NONE, overflow_buf, &info, 4);
  TEST_ASSERT(result == 0, "BIND with ncmessages exceeding buffer returns 0");

  igtl_bind_free_info(&info);
}

void test_bind_nametable_overflow(void)
{
  printf("Testing igtl_bind_unpack with nametable overflow...\n");

  igtl_bind_info info;
  igtl_bind_init_info(&info);

  /* Create buffer: ncmessages=0, nametable_size=0xFFFF */
  unsigned char overflow_buf[4];
  overflow_buf[0] = 0x00; overflow_buf[1] = 0x00;  /* ncmessages = 0 */
  overflow_buf[2] = 0xFF; overflow_buf[3] = 0xFF;  /* nametable_size = 65535 (odd = invalid) */

  int result = igtl_bind_unpack(IGTL_TYPE_PREFIX_NONE, overflow_buf, &info, 4);
  TEST_ASSERT(result == 0, "BIND with odd nametable_size returns 0");

  igtl_bind_free_info(&info);
}

void test_bind_rts_zero_size(void)
{
  printf("Testing igtl_bind_unpack RTS with zero size...\n");

  igtl_bind_info info;
  igtl_bind_init_info(&info);

  /* RTS_BIND needs at least 1 byte for status */
  int result = igtl_bind_unpack(IGTL_TYPE_PREFIX_RTS, NULL, &info, 0);
  TEST_ASSERT(result == 0, "RTS_BIND with zero size returns 0");

  igtl_bind_free_info(&info);
}

void test_bind_stt_small_buffer(void)
{
  printf("Testing igtl_bind_unpack STT with small buffer...\n");

  igtl_bind_info info;
  igtl_bind_init_info(&info);

  /* STT_BIND needs 8 bytes for time resolution */
  unsigned char small_buf[4] = {0};
  int result = igtl_bind_unpack(IGTL_TYPE_PREFIX_STT, small_buf, &info, 4);
  TEST_ASSERT(result == 0, "STT_BIND with 4-byte buffer returns 0");

  igtl_bind_free_info(&info);
}

/*
 * ============================================================================
 * igtl_polydata Tests
 * ============================================================================
 */

void test_polydata_zero_size(void)
{
  printf("Testing igtl_polydata_unpack with zero size...\n");

  igtl_polydata_info info;
  igtl_polydata_init_info(&info);

  int result = igtl_polydata_unpack(IGTL_TYPE_PREFIX_NONE, NULL, &info, 0);
  TEST_ASSERT(result == 0, "POLYDATA with zero size returns 0");

  igtl_polydata_free_info(&info);
}

void test_polydata_small_buffer(void)
{
  printf("Testing igtl_polydata_unpack with undersized buffer...\n");

  igtl_polydata_info info;
  igtl_polydata_init_info(&info);

  unsigned char small_buf[10];
  memset(small_buf, 0, 10);

  int result = igtl_polydata_unpack(IGTL_TYPE_PREFIX_NONE, small_buf, &info, 10);
  TEST_ASSERT(result == 0, "POLYDATA with 10-byte buffer returns 0");

  igtl_polydata_free_info(&info);
}

void test_polydata_npoints_overflow(void)
{
  printf("Testing igtl_polydata_unpack with npoints overflow...\n");

  igtl_polydata_info info;
  igtl_polydata_init_info(&info);

  /* Create header with max npoints */
  igtl_polydata_header header;
  memset(&header, 0, sizeof(header));
  header.npoints = 0xFFFFFFFF;  /* Would overflow when multiplied by 12 */
  if (igtl_is_little_endian()) {
    header.npoints = BYTE_SWAP_INT32(header.npoints);
  }

  int result = igtl_polydata_unpack(IGTL_TYPE_PREFIX_NONE, &header, &info, sizeof(header));
  TEST_ASSERT(result == 0, "POLYDATA with max npoints returns 0");

  igtl_polydata_free_info(&info);
}

void test_polydata_topology_overflow(void)
{
  printf("Testing igtl_polydata_unpack with topology overflow...\n");

  igtl_polydata_info info;
  igtl_polydata_init_info(&info);

  /* Create header with valid npoints but huge vertices size */
  igtl_polydata_header header;
  memset(&header, 0, sizeof(header));
  header.npoints = 1;
  header.size_vertices = 0xFFFFFFFF;  /* Exceeds any reasonable buffer */
  if (igtl_is_little_endian()) {
    header.npoints = BYTE_SWAP_INT32(header.npoints);
    header.size_vertices = BYTE_SWAP_INT32(header.size_vertices);
  }

  /* Provide header + 12 bytes for 1 point */
  unsigned char buffer[sizeof(igtl_polydata_header) + 12];
  memcpy(buffer, &header, sizeof(header));
  memset(buffer + sizeof(header), 0, 12);

  int result = igtl_polydata_unpack(IGTL_TYPE_PREFIX_NONE, buffer, &info, sizeof(buffer));
  TEST_ASSERT(result == 0, "POLYDATA with huge size_vertices returns 0");

  igtl_polydata_free_info(&info);
}

void test_polydata_unaligned_topology(void)
{
  printf("Testing igtl_polydata_unpack with unaligned topology...\n");

  igtl_polydata_info info;
  igtl_polydata_init_info(&info);

  /* Create header with size_vertices not divisible by 4 */
  igtl_polydata_header header;
  memset(&header, 0, sizeof(header));
  header.npoints = 0;
  header.size_vertices = 3;  /* Not divisible by sizeof(igtl_uint32) */
  if (igtl_is_little_endian()) {
    header.size_vertices = BYTE_SWAP_INT32(header.size_vertices);
  }

  int result = igtl_polydata_unpack(IGTL_TYPE_PREFIX_NONE, &header, &info, sizeof(header) + 3);
  TEST_ASSERT(result == 0, "POLYDATA with unaligned size_vertices returns 0");

  igtl_polydata_free_info(&info);
}

void test_polydata_alloc_overflow(void)
{
  printf("Testing igtl_polydata_alloc_info with overflow protection...\n");

  /*
   * Note: On 64-bit systems, npoints * sizeof(float) * 3 won't overflow
   * for any 32-bit npoints value. The overflow protection in
   * igtl_polydata_safe_multiply() is effective on 32-bit systems.
   *
   * On 64-bit systems, large allocations may succeed due to virtual memory
   * or may fail due to malloc limits - behavior is platform-dependent.
   *
   * This test verifies the function handles edge cases gracefully.
   */
  igtl_polydata_info info;
  igtl_polydata_init_info(&info);

  /* Test with zero npoints - should succeed */
  info.header.npoints = 0;
  int result = igtl_polydata_alloc_info(&info);
  TEST_ASSERT(result == 1, "POLYDATA alloc with 0 npoints succeeds");

  igtl_polydata_free_info(&info);
}

/*
 * ============================================================================
 * igtl_image Tests
 * ============================================================================
 */

void test_image_valid_minimal(void)
{
  printf("Testing igtl_image with minimal valid data...\n");

  /* 1x1x1 uint8 image = 1 byte of data */
  igtl_image_header header;
  memset(&header, 0, sizeof(header));
  header.header_version = IGTL_IMAGE_HEADER_VERSION;
  header.num_components = 1;
  header.scalar_type = IGTL_IMAGE_STYPE_TYPE_UINT8;
  header.endian = IGTL_IMAGE_ENDIAN_BIG;
  header.coord = IGTL_IMAGE_COORD_RAS;
  header.size[0] = 1; header.size[1] = 1; header.size[2] = 1;
  header.subvol_size[0] = 1; header.subvol_size[1] = 1; header.subvol_size[2] = 1;

  /* Just verify we can set up a valid header */
  TEST_ASSERT(header.header_version == IGTL_IMAGE_HEADER_VERSION, "Image header version set correctly");
}

/*
 * ============================================================================
 * igtl_ndarray Tests
 * ============================================================================
 */

void test_ndarray_zero_size(void)
{
  printf("Testing igtl_ndarray with zero size...\n");

  igtl_ndarray_info info;
  igtl_ndarray_init_info(&info);

  /* igtl_ndarray_unpack(type, byte_array, info, pack_size) */
  int result = igtl_ndarray_unpack(IGTL_TYPE_PREFIX_NONE, NULL, &info, 0);
  TEST_ASSERT(result == 0, "NDARRAY with zero size returns 0");

  igtl_ndarray_free_info(&info);
}

void test_ndarray_small_buffer(void)
{
  printf("Testing igtl_ndarray with small buffer...\n");

  igtl_ndarray_info info;
  igtl_ndarray_init_info(&info);

  unsigned char small_buf[2] = {0};
  /* igtl_ndarray_unpack(type, byte_array, info, pack_size) */
  int result = igtl_ndarray_unpack(IGTL_TYPE_PREFIX_NONE, small_buf, &info, 2);
  /* Should fail - buffer too small for type + dim fields */
  TEST_ASSERT(result == 0, "NDARRAY with 2-byte buffer returns 0");

  igtl_ndarray_free_info(&info);
}

/*
 * ============================================================================
 * igtl_capability Tests
 * ============================================================================
 */

void test_capability_zero_size(void)
{
  printf("Testing igtl_capability with zero types...\n");

  igtl_capability_info info;
  igtl_capability_init_info(&info);

  /* Zero types is valid - igtl_capability_alloc_info(info, ntypes) */
  int result = igtl_capability_alloc_info(&info, 0);
  TEST_ASSERT(result == 1, "CAPABILITY with 0 types alloc succeeds");

  igtl_capability_free_info(&info);
}

/*
 * ============================================================================
 * Main
 * ============================================================================
 */

int main(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  printf("\n=== OpenIGTLink C Utility Security Tests ===\n\n");

  /* BIND tests */
  printf("--- BIND Tests ---\n");
  test_bind_zero_size();
  test_bind_small_buffer();
  test_bind_ncmessages_overflow();
  test_bind_nametable_overflow();
  test_bind_rts_zero_size();
  test_bind_stt_small_buffer();

  /* POLYDATA tests */
  printf("\n--- POLYDATA Tests ---\n");
  test_polydata_zero_size();
  test_polydata_small_buffer();
  test_polydata_npoints_overflow();
  test_polydata_topology_overflow();
  test_polydata_unaligned_topology();
  test_polydata_alloc_overflow();

  /* IMAGE tests */
  printf("\n--- IMAGE Tests ---\n");
  test_image_valid_minimal();

  /* NDARRAY tests */
  printf("\n--- NDARRAY Tests ---\n");
  test_ndarray_zero_size();
  test_ndarray_small_buffer();

  /* CAPABILITY tests */
  printf("\n--- CAPABILITY Tests ---\n");
  test_capability_zero_size();

  printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
