#pragma once

#include "nullx/asio.hpp"
#include "nullx/jsonvalue.hpp"
#include "nullx/log.hpp"
#include "nullx/url.hpp"

#include <elliptics/session.hpp>
#include <elliptics/interface.h>

#include <nulla/iso_reader.hpp>

namespace ioremap { namespace nullx {

template <typename Server, typename Stream>
class on_download_json_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream> {
public:
	virtual void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) buffer;

		const auto &path = req.url().path_components();
		if (path.size() < 2) {
			NLOG_ERROR("download: on_request: url: %s, invalid path components size %ld",
					req.url().to_human_readable().c_str(), path.size());

			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		std::string bucket = url::bucket(req);
		std::string key = url::key(req, true);

		auto &headers = req.headers();
		auto egroups = headers.get("X-Ell-Groups");
		if (!egroups) {
			NLOG_ERROR("download: on_request: url: %s, there is no X-Ell-Groups header",
					req.url().to_human_readable().c_str());

			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		auto groups = elliptics::parse_groups(egroups->c_str());

		elliptics::key ekey(key);
		elliptics::session session(this->server()->session());
		session.set_groups(groups);
		session.set_namespace(bucket);
		session.transform(ekey);

		session.read_data(ekey, 0, 0).connect(std::bind(&on_download_json_base::unpack,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

private:
	void unpack(const elliptics::sync_read_result &result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("download: unpack: url: %s, read failed: %s [%d]",
					this->request().url().to_human_readable().c_str(),
					error.message().c_str(), error.code());

			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		for (auto ent = result.begin(), end = result.end(); ent != end; ++ent) {
			if (ent->error()) {
				NLOG_ERROR("download: unpack: url: %s, error result: %s [%d]",
						this->request().url().to_human_readable().c_str(),
						ent->error().message().c_str(), ent->error().code());
				continue;
			}

			try {
				const elliptics::data_pointer &file = ent->file();

				msgpack::unpacked msg;
				msgpack::unpack(&msg, file.data<char>(), file.size());

				nulla::media media;
				msg.get().convert(&media);

				size_t idx = 0;
				for (auto it = media.tracks.begin(), it_end = media.tracks.end(); it != it_end; ++it) {
					NLOG_INFO("download: unpack: url: %s, track: %ld/%ld: %s",
							this->request().url().to_human_readable().c_str(),
							idx, media.tracks.size(), it->str().c_str());

					++idx;
				}

				media_send_reply(media);
				return;
			} catch (const std::exception &e) {
				NLOG_ERROR("download: unpack: url: %s, exception: %s",
						this->request().url().to_human_readable().c_str(), e.what());
			}
		}

		this->send_reply(swarm::http_response::bad_request);
	}

	void media_send_reply(const nulla::media &media) {
		nullx::JsonValue value;
		export_meta_info_json(media, value, value.GetAllocator());

		std::string data = value.ToString();

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

	void export_meta_info_json(const nulla::media &media, rapidjson::Value &meta, rapidjson::MemoryPoolAllocator<> &allocator) {

		rapidjson::Value tracks(rapidjson::kArrayType);

		for (const auto &t: media.tracks) {
			rapidjson::Value track(rapidjson::kObjectType);

			rapidjson::Value codec_val(t.codec.c_str(), t.codec.size(), allocator);
			track.AddMember("codec", codec_val, allocator);

			rapidjson::Value mime_val(t.mime_type.c_str(), t.mime_type.size(), allocator);
			track.AddMember("mime_type", mime_val, allocator);

			track.AddMember("number", t.number, allocator);
			track.AddMember("timescale", t.timescale, allocator);
			track.AddMember("duration", t.duration, allocator);
			track.AddMember("bandwidth", t.bandwidth, allocator);

			track.AddMember("media_timescale", t.media_timescale, allocator);
			track.AddMember("media_duration", t.media_duration, allocator);

			rapidjson::Value audio(rapidjson::kObjectType);
			audio.AddMember("sample_rate", t.audio.sample_rate, allocator);
			audio.AddMember("channels", t.audio.channels, allocator);
			audio.AddMember("bits_per_sample", t.audio.bps, allocator);
			track.AddMember("audio", audio, allocator);

			rapidjson::Value video(rapidjson::kObjectType);
			video.AddMember("width", t.video.width, allocator);
			video.AddMember("height", t.video.height, allocator);
			track.AddMember("video", video, allocator);

			tracks.PushBack(track, allocator);
		}

		meta.AddMember("tracks", tracks, allocator);
	}

};

template <typename Server>
class on_download_json : public on_download_json_base<Server, on_download_json<Server>>
{
};

}} // namespace ioremap::nullx
