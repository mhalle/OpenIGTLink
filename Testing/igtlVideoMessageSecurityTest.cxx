/*=========================================================================

  Program:   OpenIGTLink Library -- Video Message Security Tests
  Language:  C++

  Copyright (c) Insight Software Consortium. All rights reserved.

  This software is distributed WITHOUT ANY WARRANTY; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

/*
 * Security tests for OpenIGTLink Video message handling.
 * These tests verify that malformed video inputs are rejected gracefully.
 */

#include "igtlMessageHeader.h"
#include "igtlTestConfig.h"
#include "igtlutil/igtl_header.h"

#if defined(OpenIGTLink_USE_H264) || defined(OpenIGTLink_USE_VP9) || defined(OpenIGTLink_USE_X265) || defined(OpenIGTLink_USE_AV1)
#include "igtlVideoMessage.h"
#include "igtlutil/igtl_video.h"
#endif

#include <string.h>
#include <limits.h>

/*
 * ============================================================================
 * StartVideoMessage Security Tests
 * ============================================================================
 */

TEST(StartVideoMessageSecurityTest, ContentSmallerThanHeader)
{
  /* Test with content smaller than STT_VIDEO header (12 bytes) */
  igtl::StartVideoMessage::Pointer msg = igtl::StartVideoMessage::New();
  igtl::MessageHeader::Pointer header = igtl::MessageHeader::New();

  unsigned char stt_header[IGTL_HEADER_SIZE];
  memset(stt_header, 0, IGTL_HEADER_SIZE);
  stt_header[0] = 0x00; stt_header[1] = 0x01;
  memcpy(stt_header + 2, "STT_VIDEO", 9);
  memcpy(stt_header + 14, "TestDevice", 10);
  /* Body size = 4 (smaller than 12-byte STT_VIDEO header) */
  stt_header[49] = 0x04;

  header->AllocatePack();
  memcpy(header->GetPackPointer(), stt_header, IGTL_HEADER_SIZE);
  header->Unpack();

  msg->SetMessageHeader(header);
  msg->AllocatePack();

  /* Put some data in body */
  memset(msg->GetPackBodyPointer(), 0, 4);

  int result = msg->Unpack(0);
  EXPECT_EQ(result, 0);
}

TEST(StartVideoMessageSecurityTest, ValidMinimalMessage)
{
  /* Test valid minimal STT_VIDEO message */
  igtl::StartVideoMessage::Pointer msg = igtl::StartVideoMessage::New();

  msg->SetDeviceName("TestVideo");
  msg->SetTimeInterval(33);  /* ~30 fps */
  msg->SetCodecType("H264");

  int result = msg->Pack();
  EXPECT_EQ(result, 1);

  /* Verify we can unpack it */
  igtl::StartVideoMessage::Pointer msg2 = igtl::StartVideoMessage::New();
  igtl::MessageHeader::Pointer header = igtl::MessageHeader::New();

  header->AllocatePack();
  memcpy(header->GetPackPointer(), msg->GetPackPointer(), IGTL_HEADER_SIZE);
  header->Unpack();

  msg2->SetMessageHeader(header);
  msg2->AllocatePack();
  memcpy(msg2->GetPackBodyPointer(), msg->GetPackBodyPointer(), msg->GetPackBodySize());

  result = msg2->Unpack(0);
  EXPECT_EQ(result != 0, true);
}

TEST(StartVideoMessageSecurityTest, CodecTypeNullTermination)
{
  /* Test that codec type is properly null-terminated even when reading full buffer */
  igtl::StartVideoMessage::Pointer msg = igtl::StartVideoMessage::New();
  igtl::MessageHeader::Pointer header = igtl::MessageHeader::New();

  /* Create proper STT_VIDEO header */
  unsigned char stt_header[IGTL_HEADER_SIZE];
  memset(stt_header, 0, IGTL_HEADER_SIZE);
  stt_header[0] = 0x00; stt_header[1] = 0x01;
  memcpy(stt_header + 2, "STT_VIDEO", 9);
  memcpy(stt_header + 14, "TestDevice", 10);
  /* Body size = 12 (IGTL_STT_VIDEO_SIZE) */
  stt_header[49] = 0x0C;

  header->AllocatePack();
  memcpy(header->GetPackPointer(), stt_header, IGTL_HEADER_SIZE);
  header->Unpack();

  msg->SetMessageHeader(header);
  msg->AllocatePack();

  /* Create body with non-null-terminated codec field */
  unsigned char stt_body[12];
  memset(stt_body, 0, 12);
  /* time_interval = 33 in network byte order */
  stt_body[0] = 0x00; stt_body[1] = 0x00; stt_body[2] = 0x00; stt_body[3] = 0x21;
  /* codec = "XXXX" (4 bytes, no null terminator in the field) */
  stt_body[4] = 'X'; stt_body[5] = 'X'; stt_body[6] = 'X'; stt_body[7] = 'X';

  memcpy(msg->GetPackBodyPointer(), stt_body, 12);

  int result = msg->Unpack(0);
  EXPECT_EQ(result != 0, true);

  /* Verify codec string is properly terminated and doesn't read garbage */
  std::string codec = msg->GetCodecType();
  EXPECT_EQ(codec.length() <= 4, true);
}

/*
 * ============================================================================
 * VideoMessage Security Tests
 * ============================================================================
 */

TEST(VideoMessageSecurityTest, ContentSmallerThanHeader)
{
  /* Test with content smaller than VIDEO header (80 bytes) */
  igtl::VideoMessage::Pointer msg = igtl::VideoMessage::New();
  igtl::MessageHeader::Pointer header = igtl::MessageHeader::New();

  unsigned char video_header[IGTL_HEADER_SIZE];
  memset(video_header, 0, IGTL_HEADER_SIZE);
  video_header[0] = 0x00; video_header[1] = 0x01;
  memcpy(video_header + 2, "VIDEO", 5);
  memcpy(video_header + 14, "TestDevice", 10);
  /* Body size = 40 (smaller than 80-byte video header) */
  video_header[49] = 0x28;

  header->AllocatePack();
  memcpy(header->GetPackPointer(), video_header, IGTL_HEADER_SIZE);
  header->Unpack();

  msg->SetMessageHeader(header);
  msg->AllocatePack();

  memset(msg->GetPackBodyPointer(), 0, 40);

  int result = msg->Unpack(0);
  EXPECT_EQ(result, 0);
}

TEST(VideoMessageSecurityTest, GetBitStreamSizeBeforeUnpack)
{
  /* Test that GetBitStreamSize returns 0 before unpacking */
  igtl::VideoMessage::Pointer msg = igtl::VideoMessage::New();

  /* Before any operation, bitstream size should be 0 */
  int size = msg->GetBitStreamSize();
  EXPECT_EQ(size, 0);
}

TEST(VideoMessageSecurityTest, SetBitStreamSize)
{
  /* Test SetBitStreamSize */
  igtl::VideoMessage::Pointer msg = igtl::VideoMessage::New();

  msg->SetBitStreamSize(1024);
  EXPECT_EQ(msg->GetBitStreamSize(), 1024);
}

TEST(VideoMessageSecurityTest, ValidMinimalMessage)
{
  /* Test creating a valid minimal video message */
  igtl::VideoMessage::Pointer msg = igtl::VideoMessage::New();

  msg->SetDeviceName("TestVideo");
  msg->SetBitStreamSize(0);
  msg->SetCodecType("H264");
  msg->SetScalarType(igtl::VideoMessage::TYPE_UINT8);
  msg->SetEndian(IGTL_VIDEO_ENDIAN_LITTLE);
  msg->SetWidth(64);
  msg->SetHeight(64);

  msg->AllocateScalars();

  int result = msg->Pack();
  EXPECT_EQ(result, 1);
}

/*
 * ============================================================================
 * StopVideoMessage Security Tests
 * ============================================================================
 */

TEST(StopVideoMessageSecurityTest, ValidEmptyMessage)
{
  /* STP_VIDEO has empty body */
  igtl::StopVideoMessage::Pointer msg = igtl::StopVideoMessage::New();
  msg->SetDeviceName("TestVideo");

  int result = msg->Pack();
  EXPECT_EQ(result, 1);
}

/*
 * ============================================================================
 * Main
 * ============================================================================
 */

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
