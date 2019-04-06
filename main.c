#include <taihen.h>
#include <psp2/paf.h>
#include <psp2/kernel/sysmem.h>

#include <libpng16/png.h>

#include <libk/string.h>

int __errno = 0;
void abort(void) {
	__builtin_trap();
}

void *malloc(size_t sz) {
	return sce_paf_private_malloc(sz);
}

void free(void *p) {
	sce_paf_private_free(p);
}

//////

tai_hook_ref_t watermark_hook, encode_hook, encode_type2_hook, reg_hook;

int get_key_int(const char *dir, const char *file, int *out) {
	if (strcmp(dir, "/CONFIG/PHOTO") == 0 && strcmp(file, "debug_screenshot") == 0) {
		*out = 1;
		return 0;
	}

	return TAI_CONTINUE(int, reg_hook, dir, file, out);
}

int place_watermark_hook() {
	return 0;
}

int encode_screenshot(void **ss_arg1, unsigned unk) {
	// set format to 2 = "raw" but we will hook and change that later
	((int*)(*ss_arg1))[8/4] = 2;

	return TAI_CONTINUE(int, encode_hook, ss_arg1, unk);
}

typedef struct picture_t picture_t;

typedef struct {
	int width;
	int height;
} dimensions_t;

typedef struct {
	void *field_0;
	void *field_4;
	void *field_8;
	int (*get_type)(picture_t *);
	int (*get_dimensions)(dimensions_t *, picture_t *);
	void *field_14;
	unsigned (*get_pixel)(picture_t *, int x, int y);
	void *field_1c;
	void *field_20;
} picture_vtable_t;

struct picture_t {
	picture_vtable_t *vptr;
};

typedef struct encode_t encode_t;

typedef struct {
	void *field_0;
	void *field_4;
	int (*is_buffer_init)(encode_t *);
	int (*append)(encode_t *, const void *buffer, size_t sz);
	void *field_10;
	void *field_14;
	void *field_18;
	void *field_1c;
	void *field_20;
} encode_vtable_t;

struct encode_t {
	encode_vtable_t *vptr;
} __attribute__((packed));

typedef struct {
	picture_t *picture;
	encode_t *encode;
	void *field_8;
} actual_encode_args_t;

typedef struct {
	int (*func)();
	unsigned field_4;
} unk_obj_t;

size_t g_png_size;

void write_func(png_structp png_ptr, png_bytep data, png_size_t length) {
	g_png_size += length;
	actual_encode_args_t *args = png_get_io_ptr(png_ptr);
	args->encode->vptr->append(args->encode, data, length);
}

enum {
	ENCODE_ERROR1 = 0x80103001,
	ENCODE_ERROR = 0x80103002,
};

int encode_type2(actual_encode_args_t *args) {
	int ret = 0;
	unsigned *pixels = NULL;
	png_structp png_ptr = NULL;
	png_infop info_ptr = NULL;
	dimensions_t wh = {0};

	encode_t *encode = args->encode;
	picture_t *picture = args->picture;

	if (!encode || !encode->vptr->is_buffer_init(encode) || !picture || !picture->vptr->get_type(picture))
		return ENCODE_ERROR;

	g_png_size = 0;
	picture->vptr->get_dimensions(&wh, picture);

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (!png_ptr)
		goto cleanup;

	info_ptr = png_create_info_struct(png_ptr);
	if (!info_ptr)
		goto cleanup;

	png_set_check_for_invalid_index(png_ptr, 0);

	png_set_IHDR(png_ptr, info_ptr, wh.width, wh.height, 8,
		PNG_COLOR_TYPE_RGBA,
		PNG_INTERLACE_NONE,
		PNG_COMPRESSION_TYPE_DEFAULT,
		PNG_FILTER_TYPE_DEFAULT);

	png_set_write_fn(png_ptr, args, write_func, NULL);

	pixels = sce_paf_private_malloc(wh.width * 4);

	png_write_info(png_ptr, info_ptr);

	for (int i = 0; i < wh.height; ++i) {
		// haven't reversed what this does, just copied from assembly
		unk_obj_t *unk = args->field_8;
		if (unk && unk->func && unk->func(unk->field_4)) {
			ret = ENCODE_ERROR1;
			goto cleanup;
		}

		for (int j = 0; j < wh.width; ++j)
			pixels[j] = picture->vptr->get_pixel(picture, j, i) | 0xFF000000u;

		png_write_row(png_ptr, (void*)pixels);
	}

	png_write_end(png_ptr, info_ptr);

cleanup:
	if (png_ptr || info_ptr)
		png_destroy_write_struct(&png_ptr, &info_ptr);

	if (pixels)
		sce_paf_private_free(pixels);

	if (ret < 0)
		return ret;

	return g_png_size;
}

int module_start() {
	tai_module_info_t info = {0};
	info.size = sizeof(info);
	taiGetModuleInfo(TAI_MAIN_MODULE, &info);

	if (info.module_nid == 0x0552F692) { // 3.60 retail
		// disable watermark
		taiHookFunctionOffset(&watermark_hook, info.modid, 0, 0x247e00, 1, place_watermark_hook);

		// enable type=2 screenshot encoding
		taiHookFunctionOffset(&encode_hook, info.modid, 0, 0x365f46, 1, encode_screenshot);

		// replace type=2 encoding with our png implementation
		taiHookFunctionOffset(&encode_type2_hook, info.modid, 0, 0x36bd22, 1, encode_type2);

		// change branch for 0x34560004 (screenshot disable) to 0x34560003 (screenshot enable)
		int value = 0x3b;
		taiInjectData(info.modid, 0, 0x248840, &value, 2);

		// change extension from jpg to png
		const char *path = "ur0:temp/screenshot/capture.png";
		taiInjectData(info.modid, 0, 0x5148b8, path, strlen(path) + 1);
	} else if (info.module_nid == 0xEAB89D5C) //3.60 Testkit
	{
		// disable watermark
		taiHookFunctionOffset(&watermark_hook, info.modid, 0, 0x240234, 1, place_watermark_hook);

		// enable type=2 screenshot encoding
		taiHookFunctionOffset(&encode_hook, info.modid, 0, 0x35c98e, 1, encode_screenshot);

		// replace type=2 encoding with our png implementation
		taiHookFunctionOffset(&encode_type2_hook, info.modid, 0, 0x36276a, 1, encode_type2);

		// change branch for 0x34560004 (screenshot disable) to 0x34560003 (screenshot enable)
		int value = 0x3b;
		taiInjectData(info.modid, 0, 0x240C74, &value, 2);

		// change extension from jpg to png
		const char *path = "ur0:temp/screenshot/capture.png";
		taiInjectData(info.modid, 0, 0x508B18, path, strlen(path) + 1);
	}else if (info.module_nid == 0x5549BF1F ||
		   info.module_nid == 0x34B4D82E ||
		   info.module_nid == 0x12DAC0F3) { // 3.65/3.67/3.68 retail
		// disable watermark
		taiHookFunctionOffset(&watermark_hook, info.modid, 0, 0x247e9c, 1, place_watermark_hook);

		// enable type=2 screenshot encoding
		taiHookFunctionOffset(&encode_hook, info.modid, 0, 0x36638a, 1, encode_screenshot);

		// replace type=2 encoding with our png implementation
		taiHookFunctionOffset(&encode_type2_hook, info.modid, 0, 0x36c166, 1, encode_type2);

		// change branch for 0x34560004 (screenshot disable) to 0x34560003 (screenshot enable)
		int value = 0x3b;
		taiInjectData(info.modid, 0, 0x2488dc, &value, 2);

		// change extension from jpg to png
		const char *path = "ur0:temp/screenshot/capture.png";
		taiInjectData(info.modid, 0, 0x514df8, path, strlen(path) + 1);
	}

	return 0;
}

int module_stop() {
	return 0;
}
