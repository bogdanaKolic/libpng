#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <sstream>
#include <setjmp.h>

#define PNG_INTERNAL
#include "png.h"

#define PNG_CLEANUP                                                              \
    if (png_handler.png_ptr)                                                     \
    {                                                                            \
        if (png_handler.row_ptr)                                                 \
            png_free(png_handler.png_ptr, png_handler.row_ptr);                  \
        if (png_handler.end_info_ptr)                                            \
            png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr, \
                                    &png_handler.end_info_ptr);                  \
        else if (png_handler.info_ptr)                                           \
            png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr, \
                                    nullptr);                                    \
        else                                                                     \
            png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr);     \
        png_handler.png_ptr = nullptr;                                           \
        png_handler.row_ptr = nullptr;                                           \
        png_handler.info_ptr = nullptr;                                          \
        png_handler.end_info_ptr = nullptr;                                      \
    }

struct BufState
{
    // using a ostringstream for the sake of simplicity, simultate File-like behavior
    std::ostringstream data;
};

struct PngObjectHandler
{
    png_infop info_ptr = nullptr;
    png_structp png_ptr = nullptr;
    png_infop end_info_ptr = nullptr;
    png_voidp row_ptr = nullptr;
    BufState *buf_state = nullptr;

    ~PngObjectHandler()
    {
        if (row_ptr)
            png_free(png_ptr, row_ptr);
        if (end_info_ptr)
            png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
        else if (info_ptr)
            png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
        else
            png_destroy_read_struct(&png_ptr, nullptr, nullptr);
        delete buf_state;
    }
};

void user_write_data(png_structp png_ptr, png_bytep data, size_t length)
{
    BufState *buf_state = static_cast<BufState *>(png_get_io_ptr(png_ptr));
    buf_state->data.write(reinterpret_cast<const char *>(data), length);
}

// Needed function for the write API, but not used in this fuzzer.
void user_flush_data(png_structp)
{
}

void *limited_malloc(png_structp, png_alloc_size_t size)
{
    if (size > 8000000)
        return nullptr;
    return malloc(size);
}

void default_free(png_structp, png_voidp ptr)
{
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8)
    {
        return 0; // too small to be a PNG
    }

    std::vector<unsigned char> v(data, data + size);
    if (png_sig_cmp(v.data(), 0, 8))
    {
        // not a PNG.
        return 0;
    }

    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;

    // Decode PNG input into RGBA buffer
    if (!png_image_begin_read_from_memory(&image, data, size))
        return 0;
    image.format = PNG_FORMAT_RGBA;

    std::vector<uint8_t> decoded(image.height * image.width * 4);
    if (!png_image_finish_read(&image, nullptr, decoded.data(), 0, nullptr))
    {
        return 0;
    }
    // Write the decoded buffer using libpng write API
    PngObjectHandler png_handler;
    png_handler.png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_handler.png_ptr)
    {
        PNG_CLEANUP
        return 0;
    }

    png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
    if (!png_handler.info_ptr)
    {
        PNG_CLEANUP
        return 0;
    }

    png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

    if (setjmp(png_jmpbuf(png_handler.png_ptr)))
    {
        PNG_CLEANUP
        return 0;
    }

    png_handler.buf_state = new BufState();
    png_set_write_fn(png_handler.png_ptr, png_handler.buf_state, user_write_data, user_flush_data);

    png_set_IHDR(png_handler.png_ptr, png_handler.info_ptr,
                 image.width, image.height,
                 8, PNG_COLOR_TYPE_RGBA,
                 PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT,
                 PNG_FILTER_TYPE_DEFAULT);

    png_write_info(png_handler.png_ptr, png_handler.info_ptr);

    // Write each row of RGBA data
    for (png_uint_32 y = 0; y < image.height; ++y)
    {
        png_write_row(png_handler.png_ptr, decoded.data() + y * image.width * 4);
    }

    png_write_end(png_handler.png_ptr, nullptr);
    PNG_CLEANUP
    return 0;
}
