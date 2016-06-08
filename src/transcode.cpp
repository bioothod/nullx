#include "nullx/transcode.hpp"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/avassert.h>
#include <libavutil/opt.h>
#include <libavutil/pixdesc.h>
}

#include <glog/logging.h>

namespace ioremap { namespace nullx {

transcoder::transcoder()
{
}
transcoder::~transcoder()
{
	for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
		avcodec_close(m_ifmt_ctx->streams[i]->codec);
		if (m_ofmt_ctx && m_ofmt_ctx->nb_streams > i && m_ofmt_ctx->streams[i] && m_ofmt_ctx->streams[i]->codec)
			avcodec_close(m_ofmt_ctx->streams[i]->codec);

		if (m_filter_ctx && m_filter_ctx[i].filter_graph)
			avfilter_graph_free(&m_filter_ctx[i].filter_graph);
	}

	av_free(m_filter_ctx);
	avformat_close_input(&m_ifmt_ctx);
	if (m_ofmt_ctx && !(m_ofmt_ctx->oformat->flags & AVFMT_NOFILE))
		avio_closep(&m_ofmt_ctx->pb);
	avformat_free_context(m_ofmt_ctx);
}

int transcoder::transcode(const std::string &input_file, const std::string &output_file)
{
	int err;

	err = open_input_file(input_file);
	if (err < 0) {
		return err;
	}

	err = open_output_file(output_file);
	if (err < 0) {
		return err;
	}

	err = init_filters();
	if (err < 0) {
		return err;
	}

	err = process_frames();
	if (err) {
		return err;
	}

	err = finish();
	if (err) {
		return err;
	}

	return 0;
}

int transcoder::open_input_file(const std::string &filename)
{
	int err;

	err = avformat_open_input(&m_ifmt_ctx, filename.c_str(), NULL, NULL);
	if (err < 0) {
		LOG(ERROR) << filename << ": could not open input file";
		return err;
	}

	err = avformat_find_stream_info(m_ifmt_ctx, NULL);
	if (err < 0) {
		LOG(ERROR) << filename  << ": could not find stream information";
		return err;
	}

	for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
		AVStream *stream;
		AVCodecContext *codec_ctx;
		stream = m_ifmt_ctx->streams[i];
		codec_ctx = stream->codec;

		/* Reencode video & audio and remux subtitles etc. */
		if (codec_ctx->codec_type == AVMEDIA_TYPE_VIDEO	|| codec_ctx->codec_type == AVMEDIA_TYPE_AUDIO) {
			/* Open decoder */
			err = avcodec_open2(codec_ctx, avcodec_find_decoder(codec_ctx->codec_id), NULL);
			if (err < 0) {
				LOG(ERROR) << filename  << ": could not find decoder for stream #" << i;
				return err;
			}
		}
	}

	av_dump_format(m_ifmt_ctx, 0, filename.c_str(), 0);
	return 0;
}

int transcoder::open_output_file(const std::string &filename)
{
	AVStream *out_stream;
	AVStream *in_stream;
	AVCodecContext *dec_ctx, *enc_ctx;
	AVCodec *encoder;
	int err;

	avformat_alloc_output_context2(&m_ofmt_ctx, NULL, NULL, filename.c_str());
	if (!m_ofmt_ctx) {
		LOG(ERROR) << filename << ": could not create output context";
		return AVERROR_UNKNOWN;
	}


	for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
		out_stream = avformat_new_stream(m_ofmt_ctx, NULL);
		if (!out_stream) {
			LOG(ERROR) << filename << ": could not allocate output stream #" << i;
			return AVERROR_UNKNOWN;
		}

		in_stream = m_ifmt_ctx->streams[i];
		dec_ctx = in_stream->codec;
		enc_ctx = out_stream->codec;

		if (dec_ctx->codec_type == AVMEDIA_TYPE_VIDEO || dec_ctx->codec_type == AVMEDIA_TYPE_AUDIO) {
			AVCodecID codec;

			// we transcode into h264/aac, since it is the only stable combination supported by HLS players
			if (dec_ctx->codec_type == AVMEDIA_TYPE_VIDEO) {
				codec = AV_CODEC_ID_H264;
			} else {
				codec = AV_CODEC_ID_AAC;
			}

			encoder = avcodec_find_encoder(codec);
			if (!encoder) {
				LOG(ERROR) << filename << ": could not find codec " << codec;
				return AVERROR_INVALIDDATA;
			}

			if (dec_ctx->codec_type == AVMEDIA_TYPE_VIDEO) {
				enc_ctx->height = dec_ctx->height;
				enc_ctx->width = dec_ctx->width;
				enc_ctx->sample_aspect_ratio = dec_ctx->sample_aspect_ratio;
				/* take first format from list of supported formats */
				enc_ctx->pix_fmt = encoder->pix_fmts[0];
				/* video time_base can be set to whatever is handy and supported by encoder */
				enc_ctx->time_base = dec_ctx->time_base;
			} else {
				enc_ctx->sample_rate = dec_ctx->sample_rate;
				enc_ctx->channel_layout = dec_ctx->channel_layout;
				enc_ctx->channels = av_get_channel_layout_nb_channels(enc_ctx->channel_layout);
				/* take first format from list of supported formats */
				enc_ctx->sample_fmt = encoder->sample_fmts[0];
				enc_ctx->time_base = (AVRational){1, enc_ctx->sample_rate};
			}

			out_stream->time_base.den = dec_ctx->sample_rate;
			out_stream->time_base.num = 1;

			if (m_ofmt_ctx->oformat->flags & AVFMT_GLOBALHEADER)
				enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

			// enable experimental features, namely AAC encoder
			enc_ctx->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;


			err = avcodec_open2(enc_ctx, encoder, NULL);
			if (err < 0) {
				LOG(ERROR) << filename << ": could not open encoder for stream #" << i;
				return err;
			}
		} else if (dec_ctx->codec_type == AVMEDIA_TYPE_UNKNOWN) {
			LOG(ERROR) << filename << ": elementary stream #" << i << " has unknown type, cannot proceed";
			return AVERROR_INVALIDDATA;
		} else {
			/* if this stream must be remuxed */
			err = avcodec_copy_context(m_ofmt_ctx->streams[i]->codec, m_ifmt_ctx->streams[i]->codec);
			if (err < 0) {
				LOG(ERROR) << filename << ": could not copy steam #" << i << " context";
				return err;
			}
		}

		if (m_ofmt_ctx->oformat->flags & AVFMT_GLOBALHEADER)
			enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

	}

	av_dump_format(m_ofmt_ctx, 0, filename.c_str(), 1);

	if (!(m_ofmt_ctx->oformat->flags & AVFMT_NOFILE)) {
		err = avio_open(&m_ofmt_ctx->pb, filename.c_str(), AVIO_FLAG_WRITE);
		if (err < 0) {
			LOG(ERROR) << filename << ": could not open output file";
			return err;
		}
	}

	/* init muxer, write output file header */
	err = avformat_write_header(m_ofmt_ctx, NULL);
	if (err < 0) {
		LOG(ERROR) << filename << ": could not write header data";
		return err;
	}

	return 0;
}

int transcoder::init_resampler(AVCodecContext *input_codec_context, AVCodecContext *output_codec_context, SwrContext **resample_context)
{
        int error;

        /**
         * Create a resampler context for the conversion.
         * Set the conversion parameters.
         * Default channel layouts based on the number of channels
         * are assumed for simplicity (they are sometimes not detected
         * properly by the demuxer and/or decoder).
         */
	*resample_context = swr_alloc_set_opts(NULL,
			av_get_default_channel_layout(output_codec_context->channels),
			output_codec_context->sample_fmt,
			output_codec_context->sample_rate,
			av_get_default_channel_layout(input_codec_context->channels),
			input_codec_context->sample_fmt,
			input_codec_context->sample_rate,
			0, NULL);
	if (!*resample_context) {
		LOG(ERROR) << "could not allocate resample context";
		return AVERROR(ENOMEM);
	}

        /**
        * Perform a sanity check so that the number of converted samples is
        * not greater than the number of samples to be converted.
        * If the sample rates differ, this case has to be handled differently
        */
        av_assert0(output_codec_context->sample_rate == input_codec_context->sample_rate);

        /** Open the resampler with the specified parameters. */
        if ((error = swr_init(*resample_context)) < 0) {
		LOG(ERROR) << "could not open resample context: " << error;
		swr_free(resample_context);
		return error;
        }

	return 0;
}

/** Initialize a FIFO buffer for the audio samples to be encoded. */
int transcoder::init_fifo(AVAudioFifo **fifo, AVCodecContext *output_codec_context)
{
	/** Create the FIFO buffer based on the specified output sample format. */
	if (!(*fifo = av_audio_fifo_alloc(output_codec_context->sample_fmt, output_codec_context->channels, 1))) {
		LOG(ERROR) << "could not allocate FIFO";
		return AVERROR(ENOMEM);
	}

	return 0;
}

int transcoder::init_audio_filter(AVCodecContext *dec_ctx, AVCodecContext *enc_ctx, AVFilterGraph *filter_graph,
		AVFilterContext **buffersrc_ctx, AVFilterContext **buffersink_ctx)
{
	char args[512];
	int err;
	AVFilter *buffersrc = NULL;
	AVFilter *buffersink = NULL;

	buffersrc = avfilter_get_by_name("abuffer");
	buffersink = avfilter_get_by_name("abuffersink");
	if (!buffersrc || !buffersink) {
		LOG(ERROR) << "could not find filtering source or sink element";
		return AVERROR_UNKNOWN;
	}

	if (!dec_ctx->channel_layout)
		dec_ctx->channel_layout = av_get_default_channel_layout(dec_ctx->channels);

	snprintf(args, sizeof(args), "time_base=%d/%d:sample_rate=%d:sample_fmt=%s:channel_layout=0x%" PRIx64,
			enc_ctx->time_base.num, enc_ctx->time_base.den, enc_ctx->sample_rate,
			av_get_sample_fmt_name(enc_ctx->sample_fmt),
			enc_ctx->channel_layout);

	err = avfilter_graph_create_filter(buffersrc_ctx, buffersrc, "in", args, NULL, filter_graph);
	if (err < 0) {
		LOG(ERROR) << "could not create audio buffer source";
		return err;
	}

	err = avfilter_graph_create_filter(buffersink_ctx, buffersink, "out", NULL, NULL, filter_graph);
	if (err < 0) {
		LOG(ERROR) << "could not create audio buffer sink";
		return err;
	}

	err = av_opt_set_bin(*buffersink_ctx, "sample_fmts",
			(uint8_t*)&enc_ctx->sample_fmt, sizeof(enc_ctx->sample_fmt),
			AV_OPT_SEARCH_CHILDREN);
	if (err < 0) {
		LOG(ERROR) << "could not set ouput sample format";
		return err;
	}

	err = av_opt_set_bin(*buffersink_ctx, "channel_layouts",
			(uint8_t*)&enc_ctx->channel_layout, sizeof(enc_ctx->channel_layout),
			AV_OPT_SEARCH_CHILDREN);
	if (err < 0) {
		LOG(ERROR) << "could not set output channel layout";
		return err;
	}

	err = av_opt_set_bin(*buffersink_ctx, "sample_rates",
			(uint8_t*)&enc_ctx->sample_rate, sizeof(enc_ctx->sample_rate),
			AV_OPT_SEARCH_CHILDREN);
	if (err < 0) {
		LOG(ERROR) << "could not set output sample rate";
		return err;
	}

	return 0;
}

int transcoder::init_video_filter(AVCodecContext *dec_ctx, AVCodecContext *enc_ctx, AVFilterGraph *filter_graph,
		AVFilterContext **buffersrc_ctx, AVFilterContext **buffersink_ctx)
{
	char args[512];
	int err;
	AVFilter *buffersrc = NULL;
	AVFilter *buffersink = NULL;

	buffersrc = avfilter_get_by_name("buffer");
	buffersink = avfilter_get_by_name("buffersink");
	if (!buffersrc || !buffersink) {
		LOG(ERROR) << "could not find filtering source or sink element";
		return AVERROR_UNKNOWN;
	}

	snprintf(args, sizeof(args),
			"video_size=%dx%d:pix_fmt=%d:time_base=%d/%d:pixel_aspect=%d/%d",
			dec_ctx->width, dec_ctx->height, dec_ctx->pix_fmt,
			dec_ctx->time_base.num, dec_ctx->time_base.den,
			dec_ctx->sample_aspect_ratio.num,
			dec_ctx->sample_aspect_ratio.den);

	err = avfilter_graph_create_filter(buffersrc_ctx, buffersrc, "in", args, NULL, filter_graph);
	if (err < 0) {
		LOG(ERROR) << "could not create video buffer source";
		return err;
	}

	err = avfilter_graph_create_filter(buffersink_ctx, buffersink, "out", NULL, NULL, filter_graph);
	if (err < 0) {
		LOG(ERROR) << "could not create video buffer sink";
		return err;
	}

	err = av_opt_set_bin(buffersink_ctx, "pix_fmts",
			(uint8_t*)&enc_ctx->pix_fmt, sizeof(enc_ctx->pix_fmt),
			AV_OPT_SEARCH_CHILDREN);
	if (err < 0) {
		LOG(ERROR) << "could not set ouput pixel format";
		return err;
	}

	return 0;
}

int transcoder::init_filter(filtering_context* fctx, AVCodecContext *dec_ctx, AVCodecContext *enc_ctx, const char *filter_spec)
{
	int err = 0;
	AVFilterContext *buffersrc_ctx = NULL;
	AVFilterContext *buffersink_ctx = NULL;
	AVFilterInOut *outputs = avfilter_inout_alloc();
	AVFilterInOut *inputs  = avfilter_inout_alloc();
	AVFilterGraph *filter_graph = avfilter_graph_alloc();

	if (!outputs || !inputs || !filter_graph) {
		err = AVERROR(ENOMEM);
		goto end;
	}

	if (dec_ctx->codec_type == AVMEDIA_TYPE_VIDEO) {
		err = init_video_filter(dec_ctx, enc_ctx, filter_graph, &buffersrc_ctx, &buffersink_ctx);
	} else if (dec_ctx->codec_type == AVMEDIA_TYPE_AUDIO) {
		err = init_audio_filter(dec_ctx, enc_ctx, filter_graph, &buffersrc_ctx, &buffersink_ctx);
		if (err)
			goto end;

		err = init_resampler(dec_ctx, enc_ctx, &fctx->resample_ctx);
		if (err)
			goto end;

		err = init_fifo(&fctx->fifo, enc_ctx);
		if (err)
			goto end;
	} else {
		err = AVERROR_UNKNOWN;
	}

	if (err)
		goto end;

	/* Endpoints for the filter graph. */
	outputs->name       = av_strdup("in");
	outputs->filter_ctx = buffersrc_ctx;
	outputs->pad_idx    = 0;
	outputs->next       = NULL;

	inputs->name       = av_strdup("out");
	inputs->filter_ctx = buffersink_ctx;
	inputs->pad_idx    = 0;
	inputs->next       = NULL;

	if (!outputs->name || !inputs->name) {
		err = AVERROR(ENOMEM);
		goto end;
	}

	err = avfilter_graph_parse_ptr(filter_graph, filter_spec, &inputs, &outputs, NULL);
	if (err < 0)
		goto end;

	err = avfilter_graph_config(filter_graph, NULL);
	if (err < 0)
		goto end;

	fctx->buffersrc_ctx = buffersrc_ctx;
	fctx->buffersink_ctx = buffersink_ctx;
	fctx->filter_graph = filter_graph;

end:
	avfilter_inout_free(&inputs);
	avfilter_inout_free(&outputs);

	return err;
}


int transcoder::init_filters(void)
{
	const char *filter_spec;
	int err;

	m_filter_ctx = (struct filtering_context *)av_malloc_array(m_ifmt_ctx->nb_streams, sizeof(*m_filter_ctx));
	if (!m_filter_ctx) {
		return AVERROR(ENOMEM);
	}

	for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
		memset(&m_filter_ctx[i], 0, sizeof(m_filter_ctx[i]));

		if (!(m_ifmt_ctx->streams[i]->codec->codec_type == AVMEDIA_TYPE_AUDIO
					|| m_ifmt_ctx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO))
			continue;


		if (m_ifmt_ctx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO) {
			filter_spec = "null"; /* passthrough (dummy) filter for video */
		} else {
			filter_spec = "anull"; /* passthrough (dummy) filter for audio */
		}

		err = init_filter(&m_filter_ctx[i], m_ifmt_ctx->streams[i]->codec, m_ofmt_ctx->streams[i]->codec, filter_spec);
		if (err)
			return err;
	}

	return 0;
}

int transcoder::encode_write_frame(AVFrame *filt_frame, unsigned int stream_index, int *got_frame)
{
	int err;
	int got_frame_local;
	AVPacket enc_pkt;

	AVStream *input_stream = m_ifmt_ctx->streams[stream_index];
	AVStream *output_stream = m_ofmt_ctx->streams[stream_index];
	AVCodecContext *input_codec = input_stream->codec;
	AVCodecContext *output_codec = output_stream->codec;

	int (*enc_func)(AVCodecContext *, AVPacket *, const AVFrame *, int *) =
		(input_codec->codec_type == AVMEDIA_TYPE_VIDEO) ? avcodec_encode_video2 : avcodec_encode_audio2;

	if (!got_frame)
		got_frame = &got_frame_local;


	/* encode filtered frame */
	enc_pkt.data = NULL;
	enc_pkt.size = 0;
	av_init_packet(&enc_pkt);

	err = enc_func(output_codec, &enc_pkt, filt_frame, got_frame);
	if (filt_frame) {
		LOG(INFO) << "encoding" <<
			": type: " << ((input_codec->codec_type == AVMEDIA_TYPE_VIDEO) ? "video" : "audio") <<
			", samples: " << filt_frame->nb_samples <<
			", input_codec_frame_size: " << input_codec->frame_size <<
			", output_codec_frame_size: " << output_codec->frame_size <<
			", error: " << err
			;
	}

	av_frame_free(&filt_frame);
	if (err < 0) {	
		return err;
	}

	if (!(*got_frame))
		return 0;

	/* prepare packet for muxing */
	enc_pkt.stream_index = stream_index;
	av_packet_rescale_ts(&enc_pkt, output_codec->time_base, output_stream->time_base);


	/* mux encoded frame */
	err = av_interleaved_write_frame(m_ofmt_ctx, &enc_pkt);
	return err;
}

int transcoder::filter_encode_write_frame(AVFrame *frame, unsigned int stream_index)
{
	int err;
	AVFrame *filt_frame;

	/* push the decoded frame into the filtergraph */
	err = av_buffersrc_add_frame_flags(m_filter_ctx[stream_index].buffersrc_ctx, frame, 0);
	if (err < 0) {
		LOG(ERROR) << "could not feed the filter graph";
		return err;
	}

	/* pull filtered frames from the filtergraph */
	while (1) {
		filt_frame = av_frame_alloc();
		if (!filt_frame) {
			err = AVERROR(ENOMEM);
			break;
		}

		err = av_buffersink_get_frame(m_filter_ctx[stream_index].buffersink_ctx, filt_frame);
		if (err < 0) {
			/* if no more frames for output - returns AVERROR(EAGAIN)
			 * if flushed and no more frames for output - returns AVERROR_EOF
			 * rewrite retcode to 0 to show it as normal procedure completion
			 */
			if (err == AVERROR(EAGAIN) || err == AVERROR_EOF)
				err = 0;

			av_frame_free(&filt_frame);
			break;
		}

		filt_frame->pict_type = AV_PICTURE_TYPE_NONE;
		err = encode_write_frame(filt_frame, stream_index, NULL);
		if (err < 0)
			break;
	}

	return err;
}

/**
 * Initialize one input frame for writing to the output file.
 * The frame will be exactly frame_size samples large.
 */
int transcoder::init_output_audio_frame(AVFrame **frame, AVCodecContext *output_codec_context, int frame_size)
{
	int err;

	/** Create a new frame to store the audio samples. */
	*frame = av_frame_alloc();
	if (*frame == NULL) {
		LOG(ERROR) << "could not allocate output frame";
		return AVERROR_EXIT;
	}

	/**
	 * Set the frame's parameters, especially its size and format.
	 * av_frame_get_buffer needs this to allocate memory for the
	 * audio samples of the frame.
	 */
	(*frame)->nb_samples     = frame_size;
	(*frame)->channel_layout = output_codec_context->channel_layout;
	(*frame)->format         = output_codec_context->sample_fmt;
	(*frame)->sample_rate    = output_codec_context->sample_rate;

	/**
	 * Allocate the samples of the created frame. This call will make
	 * sure that the audio frame can hold as many samples as specified.
	 */
	err = av_frame_get_buffer(*frame, 0);
	if (err < 0) {
		LOG(ERROR) << "could not allocate output frame samples: " << err;
		av_frame_free(frame);
		return err;
	}

	return 0;
}

int transcoder::read_frame_from_fifo(AVAudioFifo *fifo,
		AVCodecContext *output_codec_context,
		AVFrame **frame_ptr)
{
	/** Temporary storage of the output samples of the frame written to the file. */
	AVFrame *output_frame;
	/**
	 * Use the maximum number of possible samples per frame.
	 * If there is less than the maximum possible frame size in the FIFO
	 * buffer use this number. Otherwise, use the maximum possible frame size
	 */
	const int frame_size = FFMIN(av_audio_fifo_size(fifo), output_codec_context->frame_size);
	int err;

	/** Initialize temporary storage for one output frame. */
	err = init_output_audio_frame(&output_frame, output_codec_context, frame_size);
	if (err)
		return err;

	/**
	 * Read as many samples from the FIFO buffer as required to fill the frame.
	 * The samples are stored in the frame temporarily.
	 */
	err = av_audio_fifo_read(fifo, (void **)output_frame->data, frame_size);
	if (err < frame_size) {
		LOG(ERROR) << "could not read data (" << frame_size << " samples) from FIFO: " << err;
		av_frame_free(&output_frame);
		return AVERROR_EXIT;
	}

	output_frame->pts = pts;
	pts += frame_size;

	*frame_ptr = output_frame;
	return 0;
}

int transcoder::init_converted_samples(uint8_t ***converted_input_samples,
		AVCodecContext *output_codec_context,
		int frame_size)
{
	int err;

	/**
	 * Allocate as many pointers as there are audio channels.
	 * Each pointer will later point to the audio samples of the corresponding
	 * channels (although it may be NULL for interleaved formats).
	 */
	*converted_input_samples = (uint8_t **)calloc(output_codec_context->channels, sizeof(**converted_input_samples));
	if (!*converted_input_samples) {
		LOG(ERROR) << "could not allocated converted input sample pointer";
		return AVERROR(ENOMEM);
	}

	/**
	 * Allocate memory for the samples of all channels in one consecutive
	 * block for convenience.
	 */
	err = av_samples_alloc(*converted_input_samples, NULL,
			output_codec_context->channels,
			frame_size,
			output_codec_context->sample_fmt, 0);
	if (err < 0) {
		LOG(ERROR) << "could not allocated converted input samples: " << err;
		av_freep(&(*converted_input_samples)[0]);
		free(*converted_input_samples);
		*converted_input_samples = NULL;
		return err;
	}

	return 0;
}

int transcoder::convert_and_send_samples(AVFrame *frame,
		AVCodecContext *output_codec_context,
		unsigned int stream_index)
{
	filtering_context *filter_ctx = &m_filter_ctx[stream_index];
	SwrContext *resample_context = filter_ctx->resample_ctx;
	AVAudioFifo *fifo = filter_ctx->fifo;

	uint8_t **converted_input_samples = NULL;
	int err;

        err = init_converted_samples(&converted_input_samples, output_codec_context, frame->nb_samples);
	if (err)
		goto cleanup;

        /**
         * Convert the input samples to the desired output sample format.
         * This requires a temporary storage provided by converted_input_samples.
         */
	err = swr_convert(resample_context,
			converted_input_samples, frame->nb_samples,
			(const uint8_t**)frame->extended_data, frame->nb_samples);
	if (err < 0) {
		LOG(ERROR) << "could not convert input audio samples: " << err;
		goto cleanup;
	}

	err = av_audio_fifo_realloc(fifo, av_audio_fifo_size(fifo) + frame->nb_samples);
	if (err) {
		LOG(ERROR) << "could not realloc audio fifo" <<
			": " << av_audio_fifo_size(fifo) << " -> " << av_audio_fifo_size(fifo) + frame->nb_samples <<
			", error: " << err;
		goto cleanup;
	}

	err = av_audio_fifo_write(fifo, (void **)converted_input_samples, frame->nb_samples);
	if (err < frame->nb_samples) {
		LOG(ERROR) << "could not write " << frame->nb_samples << " samples into audio fifo: " << err;
        	err = AVERROR_EXIT;
		goto cleanup;
	}

	err = 0;

cleanup:
	if (converted_input_samples) {
		av_freep(&converted_input_samples[0]);
		free(converted_input_samples);
	}

	if (err)
		return err;

	LOG(INFO) << "audio" <<
		": samples: " << frame->nb_samples <<
		", output_codec_frame_size: " << output_codec_context->frame_size <<
		", fifo_size: " << av_audio_fifo_size(fifo)
		;


	return flush_fifo(stream_index, 0);
}

int transcoder::process_frames()
{
	int err;
	AVPacket packet;
	AVFrame *frame = NULL;
	unsigned int stream_index;

	int got_frame;
	int (*dec_func)(AVCodecContext *, AVFrame *, int *, const AVPacket *);

	memset(&packet, 0, sizeof(packet));
	av_init_packet(&packet);

	bool need_exit = false;

	while (!need_exit) {
		err = av_read_frame(m_ifmt_ctx, &packet);
		if (err < 0) {
			need_exit = true;

			if (err != AVERROR_EOF) {
				break;
			}

			// we have to run decoding cycle once again
			// just in case there are cached samples which have not yet been written
			err = 0;
		}

		stream_index = packet.stream_index;

		AVStream *input_stream = m_ifmt_ctx->streams[stream_index];
		AVStream *output_stream = m_ofmt_ctx->streams[stream_index];

		AVCodecContext *input_codec_context = input_stream->codec;
		AVCodecContext *output_codec_context = output_stream->codec;

		if (m_filter_ctx[stream_index].filter_graph) {
			frame = av_frame_alloc();
			if (!frame) {
				err = AVERROR(ENOMEM);
				break;
			}

			av_packet_rescale_ts(&packet, input_stream->time_base, input_codec_context->time_base);

			dec_func = (input_codec_context->codec_type == AVMEDIA_TYPE_VIDEO) ? avcodec_decode_video2 : avcodec_decode_audio4;
			err = dec_func(input_codec_context, frame, &got_frame, &packet);
			if (err < 0) {
				av_frame_free(&frame);
				LOG(ERROR) << "could not decode frame: " << err;
				break;
			}

			if (got_frame) {
				if (input_codec_context->codec_type == AVMEDIA_TYPE_AUDIO) {
					err = convert_and_send_samples(frame, output_codec_context, stream_index);
				} else {
					frame->pts = av_frame_get_best_effort_timestamp(frame);
					err = filter_encode_write_frame(frame, stream_index);
				}

				av_frame_free(&frame);
				if (err < 0) {
					LOG(ERROR) << "could not encode and write frame: " << err;
					break;
				}
			} else {
				av_frame_free(&frame);
			}
		} else {
			/* remux this frame without reencoding */
			av_packet_rescale_ts(&packet, input_stream->time_base, input_stream->time_base);

			err = av_interleaved_write_frame(m_ofmt_ctx, &packet);
			if (err < 0) {
				LOG(ERROR) << "could not write interleaved frame without reencoding: " << err;
				break;
			}
		}
		
		av_packet_unref(&packet);
	}

	av_packet_unref(&packet);

	return err;
}

int transcoder::flush_fifo(unsigned int stream_index, int final)
{
	AVStream *output_stream = m_ofmt_ctx->streams[stream_index];
	AVCodecContext *output_codec_context = output_stream->codec;
	filtering_context *filter_ctx = &m_filter_ctx[stream_index];
	AVAudioFifo *fifo = filter_ctx->fifo;
	int err;

	while (av_audio_fifo_size(fifo) >= output_codec_context->frame_size || (final && av_audio_fifo_size(fifo) > 0)) {
		AVFrame *tmp_frame;
		err = read_frame_from_fifo(fifo, output_codec_context, &tmp_frame);
		if (err) {
			return err;
		}

		err = filter_encode_write_frame(tmp_frame, stream_index);
		av_frame_free(&tmp_frame);
		if (err) {
			return err;
		}
	}

	return 0;
}

int transcoder::flush_encoder(unsigned int stream_index)
{
	int err;
	int got_frame;

	if (!(m_ofmt_ctx->streams[stream_index]->codec->codec->capabilities & AV_CODEC_CAP_DELAY))
		return 0;

	while (1) {
		err = encode_write_frame(NULL, stream_index, &got_frame);
		if (err < 0)
			break;

		if (!got_frame)
			return 0;
	}

	LOG(INFO) << "Flushed stream #" << stream_index;
	return err;
}

int transcoder::flush_output()
{
	int err;

	for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
		err = flush_fifo(i, 1);
		if (err)
			return err;

		/* flush filter */
		if (!m_filter_ctx[i].filter_graph)
			continue;

		err = filter_encode_write_frame(NULL, i);
		if (err < 0) {
			LOG(ERROR) << "could not flush filter for stream #" << i << ": " << err;
			return err;
		}

		/* flush encoder */
		err = flush_encoder(i);
		if (err < 0) {
			LOG(ERROR) << "could not flush encoder for stream #" << i << ": " << err;
			return err;
		}
	}

	return 0;
}

int transcoder::finish()
{
	int err;

	err = flush_output();
	if (err < 0) {
		return err;
	}

	err = av_write_trailer(m_ofmt_ctx);
	if (err < 0) {
		return err;
	}

	return 0;
}

}}
