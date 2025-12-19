/*
 * Copyright (c) 2025 Atle Solbakken <atle@goliathdns,no>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

 #ifndef RVA_FFMPEG_H
 #define RVA_FFMPEG_H

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/frame.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/rational.h>

#define BUFSIZE 16

#define BUFMEMBERS(type)          \
	type *entries[BUFSIZE];   \
	pthread_mutex_t mutex;    \
	int wpos;                 \
	int rpos;                 \
	int count;

typedef struct RVAPacketBuffer {
	BUFMEMBERS(AVPacket)
} RVAPacketBuffer;

typedef struct RVAFrameBuffer {
	BUFMEMBERS(AVFrame)
} RVAFrameBuffer;

typedef struct RVASharedContext {
	AVRational time_base;
	RVAPacketBuffer packet_buf;
	RVAFrameBuffer frame_buf;
} RVASharedContext;

typedef struct RVAInputContext {
	const AVInputFormat *file_iformat;
	AVFormatContext *ic;
	AVCodecContext *avctx;
	AVRational time_base;
} RVAInputContext;

typedef struct RVAEncoderContext {
	volatile int *flush_now;
	const char *filename_prefix;
	const char *filename_suffix;
	RVAFrameBuffer *frame_buf;
	AVRational time_base;
} RVAEncoderContext;

typedef struct RVADecoderContext {
	enum AVCodecID codec_id;
	AVCodecContext *avctx;
	const char *filterdescr;
	RVAFrameBuffer *frame_buf;
	RVAPacketBuffer *packet_buf;
} RVADecoderContext;

typedef struct RVAGeneratorContext {
	enum AVCodecID codec_id;
	int width;
	int height;
	RVAFrameBuffer *frame_buf;
	AVRational time_base;
} RVAGeneratorContext;

typedef struct RVAReaderContext {
	AVFormatContext *ic;
	RVAPacketBuffer *packet_buf;
} RVAReaderContext;

typedef struct RVAHeartbeat {
	time_t atomic_heartbeat;
} RVAHeartbeat;

typedef struct RVAThreadContext RVAThreadContext;

typedef int (*RVAThreadMain)(RVAThreadContext *, void *arg);

typedef struct RVAThreadContext {
	RVAHeartbeat heartbeat;
	volatile int *stop_now;
	volatile int *thread_exited;
	pthread_t thread;
	const char *name;
	RVAThreadMain main;
	int running;
	void *arg;
} RVAThreadContext;

void rva_error(const char *format, ...);
void rva_info(const char *format, ...);

int rva_open_input(RVAInputContext *ictx, const char *url);
void rva_close_input(RVAInputContext *ictx);

int rva_open_shared(RVASharedContext *ctx);
void rva_close_shared(RVASharedContext *ctx);

void rva_init_reader(
		RVAReaderContext *rctx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		const RVAInputContext *ictx,
		RVAPacketBuffer *packet_buf
);

void rva_init_decoder(
		RVADecoderContext *dctx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		const RVAInputContext *ictx,
		const char *filterdescr,
		RVAPacketBuffer *packet_buf,
		RVAFrameBuffer *frame_buf
);
void rva_init_generator(
		RVAGeneratorContext *dctx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		int width,
		int height,
		RVAFrameBuffer *frame_buf,
		AVRational time_base
);
void rva_init_encoder(
		RVAEncoderContext *ectx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		const char *filename_prefix,
		const char *filename_suffix,
		volatile int *flush_now,
		RVAFrameBuffer *frame_buf,
		AVRational time_base
);

int rva_run(
		RVAThreadContext *threads,
		int thread_count,
		volatile int *stop_now,
		volatile int *thread_exited
);

#endif
