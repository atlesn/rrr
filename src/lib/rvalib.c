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

#include "rvalib.h"

#include <assert.h>
#include <libavutil/pixfmt.h>
#include <libavutil/pixdesc.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

#define BUF_WRITE_BEGIN(buf, type) do {         \
	type *entry = buf->entries[buf->wpos];

#define BUF_WRITE_END(buf)                      \
	buf->wpos = (buf->wpos + 1) % BUFSIZE;  \
	buf->count++; } while(0)

#define BUF_READ_BEGIN(buf, type) do {          \
	type *entry = buf->entries[buf->rpos]

#define BUF_READ_END(buf)                       \
	buf->rpos = (buf->rpos + 1) % BUFSIZE;  \
	buf->count--; } while(0)

#define BUF_FULL(buf) \
	buf->count == BUFSIZE

#define BUF_EMPTY(buf) \
	buf->count == 0

#define BUF_ALLOC(buf, alloc)                         \
	err = pthread_mutex_init(&buf.mutex, NULL);   \
	if (err) {                                    \
		rva_error("Failed to initialize mutex");\
		abort();                              \
	}                                             \
	for (int i = 0; i < BUFSIZE; i++) {           \
	  buf.entries[i] = alloc();                   \
	    if (!buf.entries[i]) {                    \
	      rva_error("Failed to allocate entry\n");\
	      goto fail;                              \
	    }                                         \
	}

#define BUF_FREE(buf, type, free)             \
	pthread_mutex_lock(&buf.mutex);      \
	for (int i = 0; i < BUFSIZE; i++) {   \
	  free(&buf.entries[i]);              \
	}                                     \
	pthread_mutex_unlock(&buf.mutex);     \
	pthread_mutex_destroy(&buf.mutex)

#define PASTE(a,b) a ## b

#define QUOTE(a) #a

#define THREAD_WITH_BUF_WRITE(thread, buf, type, task) \
	PASTE(type,retry):                      \
	if (*thread->stop_now) goto done;       \
	rva_thread_heartbeat(thread);           \
	pthread_mutex_lock(&buf->mutex);        \
	if (BUF_FULL(buf)) {                    \
	  rva_error("Buffer for " QUOTE(type) " full\n"); \
	  pthread_mutex_unlock(&buf->mutex);    \
	  usleep(100 * 1000);                   \
	  goto PASTE(type,retry);               \
	}                                       \
	BUF_WRITE_BEGIN(buf, type);             \
	task                                    \
	BUF_WRITE_END(buf);                     \
	pthread_mutex_unlock(&buf->mutex);

#define THREAD_WITH_BUF_READ(thread, buf, type, task) \
	retry:                                  \
	if (*thread->stop_now) goto done;       \
	rva_thread_heartbeat(thread);           \
	pthread_mutex_lock(&buf->mutex);        \
	if (BUF_EMPTY(buf)) {                   \
	  pthread_mutex_unlock(&buf->mutex);    \
	  usleep(100 * 1000);                   \
	  goto retry;                           \
	}                                       \
	BUF_READ_BEGIN(buf, type);              \
	task                                    \
	BUF_READ_END(buf);                      \
	pthread_mutex_unlock(&buf->mutex);

static const int HEARTBEAT_TIMEOUT_S = 5;

typedef struct RVAEncoderPrivateContext {
	AVFormatContext *oc;
	AVCodecContext *avctx;
} RVAEncoderPrivateContext;

typedef enum RVAEncoderState {
	ENCODER_STATE_RUN      = 0x1,
	ENCODER_STATE_FLUSH    = 0x2
} RVAEncoderState;

typedef struct RVAFilterContext {
	AVFilterGraph *filter_graph;
	AVFilterContext *buffersrc_ctx;
	AVFilterContext *buffersink_ctx;
} RVAFilterContext;

void rva_error(const char *format, ...) {
	va_list(args); 
	va_start(args, format);

	vfprintf(stderr, format, args);

	va_end(args);
}

void rva_info(const char *format, ...) {
	va_list(args); 
	va_start(args, format);

	vfprintf(stderr, format, args);

	va_end(args);
}

static void rva_update_heartbeat(RVAHeartbeat *hb) {
	__sync_lock_test_and_set(&hb->atomic_heartbeat, time(NULL));
}

static int rva_check_heartbeat(RVAHeartbeat *hb, const char *who) {
	time_t heartbeat = __sync_fetch_and_add(&hb->atomic_heartbeat, 0);
	if (time(NULL) - heartbeat > HEARTBEAT_TIMEOUT_S) {
		rva_error("RVAHeartbeat timeout for %s\n", who);
		return 1;
	}
	return 0;
}

static RVAHeartbeat rva_make_heartbeat(void) {
	RVAHeartbeat hb = {
		.atomic_heartbeat = time(NULL)
	};
	return hb;
}

void rva_thread_heartbeat(RVAThreadContext *ctx) {
	rva_update_heartbeat(&ctx->heartbeat);
}

int rva_thread_check_heartbeat(RVAThreadContext *ctx) {
	if (rva_check_heartbeat(&ctx->heartbeat, ctx->name)) {
		pthread_cancel(ctx->thread);
		return 1;
	}
	return 0;
}

static void *rva_thread_entry(void *arg) {
	RVAThreadContext *ctx = arg;

	int ret = ctx->main(ctx, ctx->arg);

	*ctx->thread_exited = 1;

	return (void *)(intptr_t) ret;
}

int rva_start_thread(RVAThreadContext *thread) {
	int err, ret = 0;

	rva_info("Starting %s\n", thread->name);

	thread->heartbeat = rva_make_heartbeat();

	err = pthread_create(&thread->thread, NULL, rva_thread_entry, thread);
	if (err) {
		rva_error("Failed to start %s\n", thread->name);
		goto fail;
	}

	thread->running = 1;

	goto out;
	fail:
		ret = 1;
	out:
		return ret;
}

int rva_open_input(RVAInputContext *ictx, const char *url) {
	int err, ret = 0;

	AVFormatContext *ic = NULL;
	const AVInputFormat *file_iformat;
	AVCodecContext *avctx;
	AVStream *stream;
	const AVCodec *codec;
	int stream_index;

	file_iformat = av_find_input_format("rtsp");
	if (!file_iformat) {
		rva_error("Could not find input format\n");
		goto out_fail;
	}

	ic = avformat_alloc_context();
	if (!ic) {
		rva_error("Could not allocate input format context\n");
		goto out_free_format_ctx;
	}

	err = avformat_open_input(&ic, url, file_iformat, NULL);
	if (err) {
		rva_error("Error opening input: %s\n", av_err2str(err));
		assert(!ic);
		goto out_free_format_ctx;
	}

	err = avformat_find_stream_info(ic, NULL);
	if (err) {
		rva_error("Could not find stream information");
		goto out_free_format_ctx;
	}

	for (unsigned int i = 0; i < ic->nb_streams; i++) {
		AVStream *stream = ic->streams[i];
		rva_info("stream[%d] codec id %d name %s tag %u\n",
			i, stream->codecpar->codec_id, avcodec_get_name(stream->codecpar->codec_id), stream->codecpar->codec_tag);
	}

	err = av_find_best_stream(ic, AVMEDIA_TYPE_VIDEO, -1, -1, &codec, 0);
	if (err < 0) {
		rva_error("Could not find best stream\n");
		goto out_free_format_ctx;
	}
	stream_index = err;
	stream = ic->streams[stream_index];

	avctx = avcodec_alloc_context3(NULL);
	if (!avctx) {
		rva_error("Could not allocate codec context\n");
		goto out_free_format_ctx;
	}

	av_dump_format(ic, 0, url, 0);

	err = avcodec_parameters_to_context(avctx, stream->codecpar);
	if (err) {
		rva_error("Failed to set codec parameters: %s\n", av_err2str(err));
		goto out_free_codec_ctx;
	}

	err = avcodec_open2(avctx, codec, NULL);
	if (err)
		goto out_free_codec_ctx;

	avctx->pkt_timebase = stream->time_base;
	assert(avctx->codec_type == AVMEDIA_TYPE_VIDEO);

	ictx->file_iformat = file_iformat;
	ictx->ic = ic;
	ictx->avctx = avctx;
	ictx->time_base = stream->time_base;

	goto out;
	out_free_codec_ctx:
		avcodec_free_context(&avctx);
	out_free_format_ctx:
		avformat_free_context(ic);
	out_fail:
		ret = 1;
	out:
		return ret;
}

void rva_close_input(RVAInputContext *ictx) {
	avformat_close_input(&ictx->ic);
	assert(!ictx->ic);
	avcodec_free_context(&ictx->avctx);
}

static int rva_open_filter(
		RVAFilterContext *fctx,
		int have_source,
		const char *filterdescr,
		int width,
		int height,
		int pixel_format,
		AVRational time_base,
		AVRational sample_aspect_ratio
) {
	int err, ret = 0;

	const AVFilter *buffersrc = avfilter_get_by_name("buffer");
	const AVFilter *buffersink = avfilter_get_by_name("buffersink");
	AVFilterInOut *inputs = NULL;
	AVFilterInOut *outputs = NULL;
	AVFilterGraph *filter_graph = NULL;
	AVFilterContext *buffersrc_ctx = NULL;
	AVFilterContext *buffersink_ctx = NULL;
	char args_in[512];
	char args_filter[512];

	outputs = avfilter_inout_alloc();
	inputs = avfilter_inout_alloc();
	filter_graph = avfilter_graph_alloc();

	if (!outputs || !inputs || !filter_graph) {
		rva_error("Allocation of filters failed\n");
		goto fail;
	}

	if (have_source) {
		sprintf(args_in, "video_size=%dx%d:pix_fmt=%d:time_base=%d/%d:pixel_aspect=%d/%d",
			width, height, pixel_format, time_base.num, time_base.den, sample_aspect_ratio.num, sample_aspect_ratio.den);
		sprintf(args_filter, "%s", filterdescr);

		err = avfilter_graph_create_filter(&buffersrc_ctx, buffersrc, "in", args_in, NULL, filter_graph);
		if (err) {
			rva_error("Failed to create filter buffer source context\n");
			goto fail;
		}

		outputs->name       = av_strdup("in");
		outputs->filter_ctx = buffersrc_ctx;
		outputs->pad_idx    = 0;
		outputs->next       = NULL;
	}
	else {
		assert(time_base.num == 1);
		sprintf(args_filter, "%s=rate=%d:size=%dx%d,format=pix_fmts=%s,setsar=%d/%d",
			filterdescr,
			time_base.den,
			width, height,
			av_get_pix_fmt_name(pixel_format),
			sample_aspect_ratio.num, sample_aspect_ratio.den
		);
	}

	buffersink_ctx = avfilter_graph_alloc_filter(filter_graph, buffersink, "out");
	if (!buffersink_ctx) {
		rva_error("Failed to create filter buffer sink context\n");
		goto fail;
	}

	err = avfilter_init_dict(buffersink_ctx, NULL);
	if (err) {
		rva_error("Failed to initialize buffer sink context\n");
		goto fail;
	}

	inputs->name        = av_strdup("out");
	inputs->filter_ctx  = buffersink_ctx;
	inputs->pad_idx     = 0;
	inputs->next        = NULL;

	err = avfilter_graph_parse_ptr(filter_graph, args_filter, &inputs, &outputs, NULL);

	fctx->buffersrc_ctx = buffersrc_ctx;
	fctx->buffersink_ctx = buffersink_ctx;

	buffersrc_ctx = NULL;
	buffersink_ctx = NULL;
	inputs = NULL;
	outputs = NULL;

	if (err) {
		rva_error("Failed to parse graph filter description\n");
		goto fail;
	}

	err = avfilter_graph_config(filter_graph, NULL);
	if (err) {
		rva_error("Failed to configure filter graph");
		goto fail;
	}

	fctx->filter_graph = filter_graph;

	goto out;
	fail:
		avfilter_free(buffersink_ctx);
		avfilter_free(buffersrc_ctx);
		avfilter_graph_free(&filter_graph);
		avfilter_inout_free(&outputs);
		avfilter_inout_free(&inputs);
		ret = 1;
	out:
		return ret;
}

void rva_close_filter(RVAFilterContext *fctx) {
	avfilter_graph_free(&fctx->filter_graph);
}

static int rva_open_encoder(
		RVAEncoderPrivateContext *octx,
		const char *filename,
		AVRational time_base,
		enum AVPixelFormat pixel_format,
		int width,
		int height
) {
	int err, ret = 0;

	const AVOutputFormat *file_oformat;
	AVFormatContext *oc = NULL;
	AVCodecContext *avctx;
	const AVCodec *codec;
	char cwd[PATH_MAX] = {0};
	AVStream *stream;

	getcwd(cwd, sizeof(cwd));
	rva_info("CWD: %s\n", cwd);

	rva_info("Open output timebase %i/%i format %i\n", time_base.num, time_base.den, pixel_format);

	file_oformat = av_guess_format("mp4", NULL, NULL);
	if (!file_oformat) {
		rva_error("Failed to get output format\n");
		goto out_fail;
	}

	err = avformat_alloc_output_context2(&oc, file_oformat, "mp4", filename);
	if (err) {
		rva_error("Could not allocate output format context\n");
		goto out_fail;
	}

	codec = avcodec_find_encoder_by_name("libx264");
	if (!codec) {
		rva_error("Output codec not found\n");
		goto out_free_format_ctx;
	}

	stream = avformat_new_stream(oc, NULL);
	if (!stream) {
		rva_error("Failed to create output stream\n");
		goto out_free_format_ctx;
	}

	avctx = avcodec_alloc_context3(codec);
	if (!avctx) {
		rva_error("Could not allocate output codec context\n");
		goto out_free_format_ctx;
	}

	avctx->codec_id = codec->id;
	avctx->time_base = time_base;
	avctx->pkt_timebase = time_base;
	avctx->pix_fmt = pixel_format;
	avctx->width = width;
	avctx->height = height;
	avctx->qmin = 12;
	avctx->qmax = 16;
	avctx->max_qdiff = 2;
	avctx->qcompress = 0.1;
	avctx->bit_rate = 4 * 1000 * 1000;

	err = avcodec_parameters_from_context(stream->codecpar, avctx);
	if (err) {
		rva_error("Failed to set parameters on stream\n");
		goto out_free_format_ctx;
	}

	err = avcodec_open2(avctx, codec, NULL);
	if (err) {
		rva_error("Failed to open output codec\n");
		goto out_free_format_ctx;
	}

	stream->time_base = avctx->time_base;

	av_dump_format(oc, 0, filename, 1);

	// err = av_dict_set(&dict, "preset", "fast", 0);
	// if (!dict) {
	//	rva_error("Failed to create dictionary\n");
	//	goto out_free_codec_ctx;
	// }

	octx->oc = oc;
	octx->avctx = avctx;

	goto out;
//	out_free_codec_ctx:
//		avcodec_free_context(&avctx);
	out_free_format_ctx:
		avformat_free_context(oc);
	out_fail:
		ret = 1;
	out:
		return ret;
}

void rva_close_encoder(RVAEncoderPrivateContext *octx) {
	if (octx->oc) {
		avio_closep(&octx->oc->pb);
		avformat_free_context(octx->oc);
	}
	avcodec_free_context(&octx->avctx);
	memset(octx, '\0', sizeof(*octx));
}

static int rva_encoder_main(RVAThreadContext *thread, void *arg) {
	int err, ret = 0;
	RVAEncoderPrivateContext octx = {0};
	RVAEncoderContext *ctx = arg;
	RVAFrameBuffer *buf = ctx->frame_buf;
	AVFrame *frame = NULL;
	AVPacket *packet = NULL;
	int64_t packet_count = 0;
	RVAEncoderState state = 0;
	uint8_t filename_index = 0;
	char filename_indexed[PATH_MAX];
	double elapsed_s = 0.0f;

	frame = av_frame_alloc();
	if (!frame) {
		rva_error("Failed to allocate frame\n");
		goto fail;
	}

	packet = av_packet_alloc();
	if (!packet) {
		rva_error("Failed to allocate packet\n");
		goto fail;
	}

	encode:

	for (;;) {
		if (*ctx->flush_now) {
			*ctx->flush_now = 0;
			goto done;
		}

		if (state & ENCODER_STATE_FLUSH) {
			err = avcodec_send_frame(octx.avctx, NULL);
			if (err) {
				rva_error("avcodec_send_frame failed when flushing: %s\n", av_err2str(err));
				goto fail;
			}
		}
		else {
			THREAD_WITH_BUF_READ(thread, buf, AVFrame,
				av_frame_move_ref(frame, entry);
				av_frame_unref(entry);
				// rva_info("Read frame to decoder wpos %d rpos %d count %d pts %li duration %li\n",
				//	buf->wpos, buf->rpos, buf->count, frame->pts, frame->duration);
			);

			if (!octx.oc) {
				sprintf(filename_indexed, "%s%04u%s", ctx->filename_prefix, filename_index, ctx->filename_suffix);
				rva_info("Using output file %s\n", filename_indexed);
				filename_index++;
				err = rva_open_encoder(&octx, filename_indexed, ctx->time_base, frame->format, frame->width, frame->height);
				if (err)
					goto fail;
			}

			if (!(state & ENCODER_STATE_RUN)) {
				err = unlink(filename_indexed);
				if (!err || (err && errno == ENOENT)) {
					// OK
				}
				else {
					rva_error("Failed to unlink %s: %s\n", filename_indexed, strerror(errno));
					goto fail;
				}

				err = avio_open(&octx.oc->pb, filename_indexed, AVIO_FLAG_WRITE);
				if (err) {
					rva_error("Failed to open output file '%s': %s\n", filename_indexed, av_err2str(err));
					goto fail;
				}

				err = avformat_write_header(octx.oc, NULL);
				if (err) {
					rva_error("Failed to write file header: %s\n", av_err2str(err));
					goto fail;
				}

				state |= ENCODER_STATE_RUN;
			}

			elapsed_s = (double) frame->pts * ((double) octx.avctx->time_base.num / (double) octx.avctx->time_base.den);

			// printf("Elapsed %lf pts %li tb %i/%i\n", elapsed_s, frame->pts, frame->time_base.num, frame->time_base.den);

			frame->pict_type = AV_PICTURE_TYPE_NONE;

			err = avcodec_send_frame(octx.avctx, frame);
			if (err) {
				rva_error("avcodec_send_frame failed: %s\n", av_err2str(err));
				goto fail;
			}

			av_frame_unref(frame);
		}

		for (;;) {
			err = avcodec_receive_packet(octx.avctx, packet);
			if (err == AVERROR(EAGAIN)) {
				break;
			}
			else if (err == AVERROR_EOF) {
				goto write_trailer;
			}
			else if (err) {
				rva_error("avcodec_receive_packet failed: %s\n", av_err2str(err));
				goto fail;
			}

			av_packet_rescale_ts(packet, octx.avctx->time_base, octx.oc->streams[0]->time_base);

			// rva_info("Read packet from encoder pts %lli dts %lli tb %i/%i\n", (long long int) packet->pts, (long long int) packet->dts, packet->time_base.num, packet->time_base.den);

			err = av_interleaved_write_frame(octx.oc, packet);
			if (err) {
				rva_error("Failed to write packet: %s\n", strerror(errno));
				goto fail;
			}

			packet_count++;

			av_packet_unref(packet);
		}
	}

	done:

	if (*thread->stop_now && !octx.oc) {
		goto out;
	}

	state |= ENCODER_STATE_FLUSH;

	rva_info("Finalizing output after %" PRIi64 " packets\n", packet_count);

	goto encode;

	write_trailer:

	rva_info("Packet count after finalizing is %" PRIi64 " packets and elapsed time is %0.2lf" "s\n", packet_count, elapsed_s);

	err = av_write_trailer(octx.oc);
	if (err) {
		rva_error("Failed to write trailer\n");
		goto fail;
	}

	if (!(*thread->stop_now)) {
		rva_close_encoder(&octx);
		state &= ~(ENCODER_STATE_FLUSH|ENCODER_STATE_RUN);
		goto encode;
	}

	goto out;
	fail:
		ret = 1;
	out:
		rva_info("Encoder thread exiting\n");
		rva_close_encoder(&octx);
		av_frame_free(&frame);
		av_packet_free(&packet);
		return ret;
}

static int rva_decoder_main(RVAThreadContext *thread, void *arg) {
	int err, ret = 0;
	RVADecoderContext *ctx = arg;
	RVAFilterContext fctx = {0};
	AVFrame *frame = NULL, *filt_frame = NULL;
	AVPacket *packet = NULL;
	RVAPacketBuffer *packet_buf = ctx->packet_buf;
	RVAFrameBuffer *frame_buf = ctx->frame_buf;

	frame = av_frame_alloc();
	if (!frame) {
		rva_error("Failed to allocate frame\n");
		goto fail;
	}

	filt_frame = av_frame_alloc();
	if (!filt_frame) {
		rva_error("Failed to allocate frame\n");
		goto fail;
	}

	err = rva_open_filter(&fctx, 1 /* Has source */, ctx->filterdescr,
		ctx->avctx->width, ctx->avctx->height,
		ctx->avctx->pix_fmt, ctx->avctx->pkt_timebase, ctx->avctx->sample_aspect_ratio);
	if (err)
		goto fail;

	for (;;) {
		THREAD_WITH_BUF_READ(thread, packet_buf, AVPacket,
			packet = av_packet_alloc();
			if (!packet) {
				rva_error("Failed to allocate packet\n");
				goto fail;
			}
			av_packet_ref(packet, entry);
			av_packet_unref(entry);
		);

		err = avcodec_send_packet(ctx->avctx, packet);
		if (err) {
			rva_error("avcodec_send_packet dropped failed\n");
			goto fail;
		}
		av_packet_free(&packet);

		for (;;) {
			err = avcodec_receive_frame(ctx->avctx, frame);
			if (err == AVERROR(EAGAIN)) {
				// No frames
				break;
			}
			else if (err >= 0) {
				err = av_buffersrc_add_frame_flags(fctx.buffersrc_ctx, frame, AV_BUFFERSRC_FLAG_KEEP_REF);
				if (err) {
					rva_error("Failed to add frame to filter graph\n");
					goto fail;
				}

				for (;;) {
					err = av_buffersink_get_frame(fctx.buffersink_ctx, filt_frame);
					if (err == AVERROR(EAGAIN) || err == AVERROR_EOF) {
						break;
					}
					else if (err < 0) {
						rva_error("Failed to get frame from filter graph\n");
						goto fail;
					}
					THREAD_WITH_BUF_WRITE(thread, frame_buf, AVFrame,
						av_frame_move_ref(entry, filt_frame);
					);
				}
			}
			else {
				rva_error("avcodec_receive_frame failed: %s\n", av_err2str(err));
				goto fail;
			}
		}
	}

	goto done;
	fail:
		ret = 1;
	done:
		rva_info("Decoder thread exiting\n");
		rva_close_filter(&fctx);
		av_packet_free(&packet);
		av_frame_free(&filt_frame);
		av_frame_free(&frame);
		return ret;
}

static int64_t rva_get_time(void) {
	struct timeval tv;

	gettimeofday(&tv, NULL);

	int64_t tv_sec = tv.tv_sec;
	int64_t tv_factor = 1000000;
	int64_t tv_usec = tv.tv_usec;

	return tv_sec * tv_factor + tv_usec;
}

static int rva_generator_main(RVAThreadContext *thread, void *arg) {
	int err, ret = 0;
	RVAGeneratorContext *ctx = arg;
	RVAFilterContext fctx = {0};
	AVFrame *filt_frame = NULL;
	RVAFrameBuffer *frame_buf = ctx->frame_buf;

	filt_frame = av_frame_alloc();
	if (!filt_frame) {
		rva_error("Failed to allocate frame\n");
		goto fail;
	}

	AVRational aspect_ratio = {
		.num = 1,
		.den = 1
	};

	err = rva_open_filter(&fctx, 0 /* Has not source */, "testsrc",
		ctx->width, ctx->height,
		AV_PIX_FMT_YUV420P, ctx->time_base, aspect_ratio);
	if (err)
		goto fail;

	int64_t frames = 0;
	int64_t begin = rva_get_time();

	assert(ctx->time_base.num == 1);

	for (;;) {
		again:
		err = av_buffersink_get_frame(fctx.buffersink_ctx, filt_frame);
		if (err == AVERROR(EAGAIN)) {
			usleep(100 * 1000);
			goto again;
		}
		else if (err == AVERROR_EOF) {
			break;
		}
		else if (err < 0) {
			rva_error("Failed to get frame from filter graph\n");
			goto fail;
		}

		frames++;

		int64_t now = rva_get_time();
		int64_t expected = ((now - begin) * ctx->time_base.den) / (1 * 1000 * 1000);
		int64_t diff = frames - expected;

		if (diff > 0) {
			usleep(((double) diff / (double) ctx->time_base.den) * 1 * 1000 * 1000);
		}

		THREAD_WITH_BUF_WRITE(thread, frame_buf, AVFrame,
			av_frame_move_ref(entry, filt_frame);
		);
	}

	goto done;
	fail:
		ret = 1;
	done:
		rva_info("Generator thread exiting\n");
		rva_close_filter(&fctx);
		av_frame_free(&filt_frame);
		return ret;
}

static int rva_reader_main(RVAThreadContext *thread, void *arg) {
	int err, ret = 0;
	RVAReaderContext *ctx = arg;
	RVAPacketBuffer *buf = ctx->packet_buf;
	AVPacket *packet = NULL;

	packet = av_packet_alloc();
	if (!packet) {
		rva_error("Failed to allocate packet\n");
		goto fail;
	}

	for (;;) {
		for (;;) {
			err = av_read_frame(ctx->ic, packet);
			if (err) {
				if (err == AVERROR(EAGAIN))
					break;
				rva_error("Failed to read frame: %s\n", av_err2str(err));
				goto fail;
			}
			else {
				THREAD_WITH_BUF_WRITE(thread, buf, AVPacket,
					av_packet_move_ref(entry, packet);
					// rva_info("Read pkt size %d wpos %d rpos %d count %d\n", entry->size, buf->wpos, buf->rpos, buf->count);
				);
			}
		}
	}

	goto done;
	fail:
		ret = 1;
	done:
		rva_info("Reader thread exiting\n");
		av_packet_free(&packet);
		return ret;
}

int rva_open_shared(RVASharedContext *ctx) {
	int err, ret = 0;

	BUF_ALLOC(ctx->packet_buf, av_packet_alloc);
	BUF_ALLOC(ctx->frame_buf, av_frame_alloc);

	goto out;
	fail:
		ret = 1;
	out:
	return ret;
}

void rva_close_shared(RVASharedContext *ctx) {
	BUF_FREE(ctx->frame_buf, AVFrame, av_frame_free);
	BUF_FREE(ctx->packet_buf, AVPacket, av_packet_free);
}

void rva_init_reader(
		RVAReaderContext *rctx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		const RVAInputContext *ictx,
		RVAPacketBuffer *packet_buf
) {
	memset(rctx, '\0', sizeof(*rctx));
	memset(tctx, '\0', sizeof(*tctx));

	rctx->ic = ictx->ic;
	rctx->packet_buf = packet_buf;

	tctx->arg = rctx;
	tctx->main = rva_reader_main;
	tctx->name = "reader thread";
	tctx->stop_now = stop_now;
	tctx->thread_exited = thread_exited;
}

void rva_init_decoder(
		RVADecoderContext *dctx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		const RVAInputContext *ictx,
		const char *filterdescr,
		RVAPacketBuffer *packet_buf,
		RVAFrameBuffer *frame_buf
) {
	memset(dctx, '\0', sizeof(*dctx));
	memset(tctx, '\0', sizeof(*tctx));

	dctx->avctx = ictx->avctx,
	dctx->filterdescr = filterdescr,
	dctx->packet_buf = packet_buf;
	dctx->frame_buf = frame_buf;

	tctx->arg = dctx;
	tctx->main = rva_decoder_main;
	tctx->name = "decoder thread";
	tctx->stop_now = stop_now;
	tctx->thread_exited = thread_exited;
}

void rva_init_generator(
		RVAGeneratorContext *gctx,
		RVAThreadContext *tctx,
		volatile int *stop_now,
		volatile int *thread_exited,
		int width,
		int height,
		RVAFrameBuffer *frame_buf,
		AVRational time_base
) {
	memset(gctx, '\0', sizeof(*gctx));
	memset(tctx, '\0', sizeof(*tctx));

	gctx->frame_buf = frame_buf;
	gctx->time_base = time_base;
	gctx->width = width;
	gctx->height = height;

	tctx->arg = gctx;
	tctx->main = rva_generator_main;
	tctx->name = "generator thread";
	tctx->stop_now = stop_now;
	tctx->thread_exited = thread_exited;
}

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
) {
	memset(ectx, '\0', sizeof(*ectx));
	memset(tctx, '\0', sizeof(*tctx));

	ectx->filename_prefix = filename_prefix;
	ectx->filename_suffix = filename_suffix;
	ectx->flush_now = flush_now;
	ectx->frame_buf = frame_buf;
	ectx->time_base = time_base;

	tctx->arg = ectx;
	tctx->main = rva_encoder_main;
	tctx->name = "encoder thread";
	tctx->stop_now = stop_now;
	tctx->thread_exited = thread_exited;
}

int rva_run(
		RVAThreadContext *threads,
		int thread_count,
		volatile int *stop_now,
		volatile int *thread_exited
) {
	int err, ret = 0;
	void *res;

	for (int i = 0; i < thread_count; i++) {
		RVAThreadContext *thread = &threads[i];

		if (!thread->main)
			continue;

		err = rva_start_thread(thread);
		if (err)
			goto fail;
	}

	for (;;) {
		int running = 0;

		for (int i = 0; i < thread_count; i++) {
			RVAThreadContext *thread = &threads[i];

			if (!thread->running)
				continue;
			running = 1;

			if (rva_thread_check_heartbeat(thread)) {
				goto fail;
			}
		}

		if (*stop_now || *thread_exited || !running) {
			break;
		}

		usleep(100 * 1000);
	}

	goto out;
	fail:
		ret = 1;
	out:
		rva_info("Main thread exiting\n");
		*stop_now = 1;
		for (int i = 0; i < thread_count; i++) {
			RVAThreadContext *thread = &threads[i];

			if (thread->running) {
				pthread_join(thread->thread, &res);
				rva_info("Joined with %s\n", thread->name);
				if ((intptr_t) res)
					ret = 1;
			}
		}
		return ret;
}
