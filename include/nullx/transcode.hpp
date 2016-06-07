#pragma once

#include <ribosome/fpool.hpp>

#include <string>

extern "C" {
#include <libavfilter/avfilter.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libswresample/swresample.h>	
}

namespace ioremap { namespace nullx {

class transcoder {
public:
	transcoder();
	~transcoder();

	int transcode(const std::string &input_file, const std::string &output_file);

private:
	AVFormatContext *m_ifmt_ctx = NULL;
	AVFormatContext *m_ofmt_ctx = NULL;

	struct filtering_context {
		AVFilterContext *buffersink_ctx = NULL;
		AVFilterContext *buffersrc_ctx = NULL;
		AVFilterGraph *filter_graph = NULL;

		SwrContext *resample_ctx = NULL;
		AVAudioFifo *fifo;
	} *m_filter_ctx = NULL;

	uint64_t pts = 0;

	int open_input_file(const std::string &filename);
	int open_output_file(const std::string &filename);

	int init_audio_filter(AVCodecContext *dec_ctx, AVCodecContext *enc_ctx, AVFilterGraph *filter_graph,
			AVFilterContext **buffersrc_ctx, AVFilterContext **buffersink_ctx);
	int init_video_filter(AVCodecContext *dec_ctx, AVCodecContext *enc_ctx, AVFilterGraph *filter_graph,
			AVFilterContext **buffersrc_ctx, AVFilterContext **buffersink_ctx);

	int init_resampler(AVCodecContext *input_codec_context, AVCodecContext *output_codec_context, SwrContext **resample_context);
	int init_fifo(AVAudioFifo **fifo, AVCodecContext *output_codec_context);

	int init_filter(filtering_context* fctx, AVCodecContext *dec_ctx, AVCodecContext *enc_ctx, const char *filter_spec);
	int init_filters(void);

	int init_converted_samples(uint8_t ***converted_input_samples,
			AVCodecContext *output_codec_context,
			int frame_size);
	int init_output_audio_frame(AVFrame **frame, AVCodecContext *output_codec_context, int frame_size);
	int convert_and_send_samples(AVFrame *frame, AVCodecContext *output_codec_context, unsigned int stream_index);
	int read_frame_from_fifo(AVAudioFifo *fifo,
			AVCodecContext *output_codec_context,
			AVFrame **frame_ptr);

	int filter_encode_write_frame(AVFrame *frame, unsigned int stream_index);
	int encode_write_frame(AVFrame *filt_frame, unsigned int stream_index, int *got_frame);
	int process_frames();

	int flush_encoder(unsigned int stream_index);
	int flush_filters();
	int finish();
};

class transcode_controller {
public:
	transcode_controller(int num_workers);

private:
	ribosome::fpool::controller m_ctl;

	ribosome::fpool::message transcode(const ribosome::fpool::message &msg);
};

}} // namespace ioremap::nullx
