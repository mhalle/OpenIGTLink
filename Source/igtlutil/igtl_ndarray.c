/*=========================================================================

  Program:   The OpenIGTLink Library
  Language:  C
  Web page:  http://openigtlink.org/

  Copyright (c) Insight Software Consortium. All rights reserved.

  This software is distributed WITHOUT ANY WARRANTY; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

#include <stdlib.h>
#include <string.h>

#include "igtl_ndarray.h"
#include "igtl_util.h"


void igtl_export igtl_ndarray_init_info(igtl_ndarray_info * info)
{
  info->type  = 0;
  info->dim   = 0;
  info->size  = NULL;
  info->array = NULL;
}


/* Calculate number of bytes / element */
igtl_uint32 igtl_ndarray_get_nbyte(int type)
{
  igtl_uint32 bytes;

  switch (type)
    {
    case IGTL_NDARRAY_STYPE_TYPE_INT8:
    case IGTL_NDARRAY_STYPE_TYPE_UINT8:
      bytes = 1;
      break;
    case IGTL_NDARRAY_STYPE_TYPE_INT16:
    case IGTL_NDARRAY_STYPE_TYPE_UINT16:
      bytes = 2;
      break;
    case IGTL_NDARRAY_STYPE_TYPE_INT32:
    case IGTL_NDARRAY_STYPE_TYPE_UINT32:
    case IGTL_NDARRAY_STYPE_TYPE_FLOAT32:
      bytes = 4;
      break;
    case IGTL_NDARRAY_STYPE_TYPE_FLOAT64:
      bytes = 8;
      break;
    case IGTL_NDARRAY_STYPE_TYPE_COMPLEX:
      bytes = 16;
      break;
    default:
      bytes = 0;
      break;
    }

  return bytes;
}


int igtl_export igtl_ndarray_alloc_info(igtl_ndarray_info * info, const igtl_uint16 * size)
{
  int i;
  igtl_uint64 len;
  igtl_uint32 element_size;
  igtl_uint64 array_size;
  const igtl_uint64 maxVal = ~(igtl_uint64)0;

  if (info->size == NULL && info->array == NULL)
    {
    /* Security: Validate dimension is reasonable (max 255 dimensions) */
    if (info->dim == 0 || info->dim > 255)
      {
      return 0;
      }

    info->size = malloc(sizeof(igtl_uint16) * (igtl_uint16) info->dim);
    if (info->size == NULL)
      {
      return 0;
      }
    len = 1;

    for (i = 0; i < info->dim; i ++)
      {
      info->size[i] = size[i];
      /* Security: Check for multiplication overflow */
      if (size[i] != 0 && len > maxVal / size[i])
        {
        free(info->size);
        info->size = NULL;
        return 0;  /* Overflow would occur */
        }
      len *= size[i];
      }

    element_size = igtl_ndarray_get_nbyte(info->type);
    if (element_size == 0)
      {
      free(info->size);
      info->size = NULL;
      return 0;  /* Invalid type */
      }

    /* Security: Check for multiplication overflow in array size */
    if (len > maxVal / element_size)
      {
      free(info->size);
      info->size = NULL;
      return 0;  /* Overflow would occur */
      }
    array_size = element_size * len;

    info->array = malloc((size_t)array_size);

    if (info->array == NULL)
      {
      free(info->size);
      info->size = NULL;
      return 0;
      }

    return 1;
    }
  else
    {
    return 0;
    }
}


int igtl_export igtl_ndarray_free_info(igtl_ndarray_info * info)
{
  if (info->size)
    {
    free(info->size);
    }
  if (info->array)
    {
    free(info->array);
    }

  return 1;
}


int igtl_export igtl_ndarray_unpack(int type, void * byte_array, igtl_ndarray_info * info, igtl_uint64 pack_size)
{
  char * ptr;
  char * ptr_end;
  igtl_uint16 dim;
  igtl_uint16 * size;
  igtl_uint16 i;
  igtl_uint64 len;
  igtl_uint32 element_size;
  igtl_uint64 array_data_size;
  igtl_uint64 expected_size;

  igtl_uint16 * ptr16_src;
  igtl_uint16 * ptr16_src_end;
  igtl_uint16 * ptr16_dst;

  igtl_uint32 * ptr32_src;
  igtl_uint32 * ptr32_src_end;
  igtl_uint32 * ptr32_dst;

  igtl_uint64 * ptr64_src;
  igtl_uint64 * ptr64_src_end;
  igtl_uint64 * ptr64_dst;


  if (byte_array == NULL || info == NULL)
    {
    return 0;
    }

  /* Security: Minimum size check (type + dim = 2 bytes) */
  if (pack_size < 2)
    {
    return 0;
    }

  igtl_ndarray_init_info(info);
  ptr = (char *) byte_array;
  ptr_end = ptr + pack_size;

  /*** Type field ***/
  info->type = * (igtl_uint8 *) ptr;
  ptr ++;

  /*** Dimension field ***/
  info->dim  = * (igtl_uint8 *) ptr;
  ptr ++;

  /* Security: Validate dimension and check size array fits in buffer */
  dim = info->dim;
  if (dim == 0 || dim > 255)
    {
    return 0;
    }

  /* Security: Check that size array fits within pack_size */
  /* Header is 2 bytes, size array is dim * 2 bytes */
  if (pack_size < (igtl_uint64)(2 + sizeof(igtl_uint16) * dim))
    {
    return 0;
    }

  /*** Size array field ***/
  size = (igtl_uint16 *) ptr;
  if (igtl_is_little_endian())
    {
    /* Change byte order -- this overwrites memory area for the pack !!*/
    for (i = 0; i < dim; i ++)
      {
      size[i] = BYTE_SWAP_INT16(size[i]);
      }
    }

  /* Security: igtl_ndarray_alloc_info now has overflow checks */
  if (igtl_ndarray_alloc_info(info, size) == 0)
    {
    /* Restore byte order before returning */
    if (igtl_is_little_endian())
      {
      for (i = 0; i < dim; i ++)
        {
        size[i] = BYTE_SWAP_INT16(size[i]);
        }
      }
    return 0;
    }

  memcpy(info->size, size, sizeof(igtl_uint16) * dim);
  if (igtl_is_little_endian())
    {
    /* Restore the overwritten memory area */
    /* Don't use size[] array after this !! */
    for (i = 0; i < dim; i ++)
      {
      size[i] = BYTE_SWAP_INT16(size[i]);
      }
    }
  ptr += sizeof(igtl_uint16) * dim;

  /*** N-D array field ***/
  /* Calculate number of elements in N-D array */
  len = 1;
  for (i = 0; i < dim; i ++)
    {
    len *= info->size[i];
    }

  element_size = igtl_ndarray_get_nbyte(info->type);
  if (element_size == 0)
    {
    igtl_ndarray_free_info(info);
    return 0;
    }

  /* Security: Validate that array data fits within pack_size */
  array_data_size = len * element_size;
  expected_size = 2 + sizeof(igtl_uint16) * dim + array_data_size;
  if (pack_size < expected_size)
    {
    igtl_ndarray_free_info(info);
    return 0;  /* Pack too small for claimed array size */
    }

  /* Copy array */
  if (element_size == 1 || !igtl_is_little_endian())
    {
    /* If single-byte data type is used or the program runs on a big-endian machine,
       just copy the array from the pack to the structure */
    memcpy(info->array, ptr, (size_t)array_data_size);
    }
  else if (element_size == 2) /* 16-bit */
    {
    ptr16_src = (igtl_uint16 *) ptr;
    ptr16_src_end = ptr16_src + len;
    ptr16_dst = (igtl_uint16 *) info->array;
    while (ptr16_src < ptr16_src_end)
      {
      *ptr16_dst = BYTE_SWAP_INT16(*ptr16_src);
      ptr16_dst ++;
      ptr16_src ++;
      }
    }
  else if (element_size == 4) /* 32-bit */
    {
    ptr32_src = (igtl_uint32 *) ptr;
    ptr32_src_end = ptr32_src + len;
    ptr32_dst = (igtl_uint32 *) info->array;
    while (ptr32_src < ptr32_src_end)
      {
      *ptr32_dst = BYTE_SWAP_INT32(*ptr32_src);
      ptr32_dst ++;
      ptr32_src ++;
      }
    }
  else /* 64-bit or Complex type */
    {
    ptr64_src = (igtl_uint64 *) ptr;
    /* Adding number of elements to the pointer -- 64-bit: len * 1; Complex: len * 2*/
    ptr64_src_end = ptr64_src + len * element_size/8;
    ptr64_dst = (igtl_uint64 *) info->array;
    while (ptr64_src < ptr64_src_end)
      {
      *ptr64_dst = BYTE_SWAP_INT64(*ptr64_src);
      ptr64_dst ++;
      ptr64_src ++;
      }
    }

  return 1;

}


int igtl_export igtl_ndarray_pack(igtl_ndarray_info * info, void * byte_array, int type)
{
  char * ptr;
  igtl_uint16 dim;
  igtl_uint16 * size;
  igtl_uint16 i;
  igtl_uint64 len;

  igtl_uint16 * ptr16_src;
  igtl_uint16 * ptr16_src_end;
  igtl_uint16 * ptr16_dst;

  igtl_uint32 * ptr32_src;
  igtl_uint32 * ptr32_src_end;
  igtl_uint32 * ptr32_dst;

  igtl_uint64 * ptr64_src;
  igtl_uint64 * ptr64_src_end;
  igtl_uint64 * ptr64_dst;


  if (byte_array == NULL || info == NULL)
    {
    return 0;
    }

  ptr = (char *) byte_array;

  /*** Type field ***/
  * (igtl_uint8 *) ptr = info->type;
  ptr ++;

  /*** Dimension field ***/
  *  (igtl_uint8 *) ptr = info->dim;
  ptr ++;

  /*** Size array field ***/
  size = (igtl_uint16 *) ptr;
  if (igtl_is_little_endian())
    {
    for (i = 0; i < info->dim; i ++)
      {
      size[i] = BYTE_SWAP_INT16(info->size[i]);
      }
    }
  else
    {
    memcpy(ptr, info->size, sizeof(igtl_uint16) * info->dim);
    }

  dim = info->dim;
  ptr += sizeof(igtl_uint16) * dim;

  /*** N-D array field ***/
  /* Calculate number of elements in N-D array */
  len = 1;
  for (i = 0; i < dim; i ++)
    {
    len *= info->size[i];
    }

  /* Copy array */
  if (igtl_ndarray_get_nbyte(info->type) == 1 || !igtl_is_little_endian())
    {
    /* If single-byte data type is used or the program runs on a big-endian machine,
       just copy the array from the pack to the strucutre */
    memcpy(ptr, info->array, (size_t) (len * igtl_ndarray_get_nbyte(info->type)));
    }
  else if (igtl_ndarray_get_nbyte(info->type) == 2) /* 16-bit */
    {
    ptr16_src = (igtl_uint16 *) info->array;
    ptr16_src_end = ptr16_src + len;
    ptr16_dst = (igtl_uint16 *) ptr;
    while (ptr16_src < ptr16_src_end)
      {
      *ptr16_dst = BYTE_SWAP_INT16(*ptr16_src);
      ptr16_dst ++;
      ptr16_src ++;
      }
    }
  else if (igtl_ndarray_get_nbyte(info->type) == 4) /* 32-bit */
    {
    ptr32_src = (igtl_uint32 *) info->array;
    ptr32_src_end = ptr32_src + len;
    ptr32_dst = (igtl_uint32 *) ptr;
    while (ptr32_src < ptr32_src_end)
      {
      *ptr32_dst = BYTE_SWAP_INT32(*ptr32_src);
      ptr32_dst ++;
      ptr32_src ++;
      }
    }
  else /* 64-bit or Complex type */
    {
    ptr64_src = (igtl_uint64 *) info->array;
    /* Adding number of elements to the pointer -- 64-bit: len * 1; Complex: len * 2*/
    ptr64_src_end = ptr64_src + len * igtl_ndarray_get_nbyte(info->type)/8;
    ptr64_dst = (igtl_uint64 *) ptr;
    while (ptr64_src < ptr64_src_end)
      {
      *ptr64_dst = BYTE_SWAP_INT64(*ptr64_src);
      ptr64_dst ++;
      ptr64_src ++;
      }
    }

  return 1;

}


igtl_uint64 igtl_export igtl_ndarray_get_size(igtl_ndarray_info * info, int type)
{
  igtl_uint64 len;
  igtl_uint64 data_size;
  igtl_uint16 i;
  igtl_uint16 dim;
  
  dim = info->dim;
  len = 1;
  for (i = 0; i < dim; i ++)
    {
    len *= (igtl_uint64)info->size[i];
    }

  data_size = sizeof(igtl_uint8) * 2 + sizeof(igtl_uint16) * (igtl_uint64) dim
    + len * igtl_ndarray_get_nbyte(info->type);

  return data_size;

}


igtl_uint64 igtl_export igtl_ndarray_get_crc(igtl_ndarray_info * info, int type, void* data)
{
  igtl_uint64   crc;
  igtl_uint64   data_size;
  
  data_size = igtl_ndarray_get_size(info, type);

  crc = crc64(0, 0, 0);
  crc = crc64((unsigned char*) data, data_size, crc);

  return crc;
}
