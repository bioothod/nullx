#pragma once

#include "nullx/asio.hpp"
#include "nullx/jsonvalue.hpp"
#include "nullx/log.hpp"
#include "nullx/multipart/MultipartReader.h"
#include "nullx/url.hpp"

#include <swarm/url.hpp>

#include <elliptics/session.hpp>
#include <elliptics/interface.h>

#include <ribosome/timer.hpp>

#include <ebucket/bucket.hpp>

#include <nulla/iso_reader.hpp>
#include <nulla/utils.hpp>

namespace ioremap { namespace nullx {

static inline elliptics::data_pointer create_data(const boost::asio::const_buffer &buffer)
{
	return elliptics::data_pointer::from_raw(
		const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
		boost::asio::buffer_size(buffer)
	);
}

struct upload_completion {
	template <typename Allocator>
	static void fill_upload_reply(const elliptics::write_result_entry &entry,
			rapidjson::Value &result_object, Allocator &allocator) {
		char id_str[2 * DNET_ID_SIZE + 1];
		dnet_dump_id_len_raw(entry.command()->id.id, DNET_ID_SIZE, id_str);
		rapidjson::Value id_str_value(id_str, 2 * DNET_ID_SIZE, allocator);
		result_object.AddMember("id", id_str_value, allocator);

		char csum_str[2 * DNET_ID_SIZE + 1];
		dnet_dump_id_len_raw(entry.file_info()->checksum, DNET_ID_SIZE, csum_str);
		rapidjson::Value csum_str_value(csum_str, 2 * DNET_ID_SIZE, allocator);
		result_object.AddMember("csum", csum_str_value, allocator);

		if (entry.file_info()->flen > 1) {
			// copy filename without trailing 0-byte
			rapidjson::Value filename_value(entry.file_path(), entry.file_info()->flen - 1, allocator);
			result_object.AddMember("filename", filename_value, allocator);
		}

		result_object.AddMember("group", entry.command()->id.group_id, allocator);
		result_object.AddMember("backend", entry.command()->backend_id, allocator);
		result_object.AddMember("size", entry.file_info()->size, allocator);
		result_object.AddMember("offset-within-data-file", entry.file_info()->offset,
				allocator);

		rapidjson::Value tobj;
		JsonValue::set_time(tobj, allocator,
				entry.file_info()->mtime.tsec,
				entry.file_info()->mtime.tnsec / 1000);
		result_object.AddMember("mtime", tobj, allocator);

		char addr_str[128];
		dnet_addr_string_raw(entry.storage_address(), addr_str, sizeof(addr_str));

		rapidjson::Value server_addr(addr_str, strlen(addr_str), allocator);
		result_object.AddMember("server", server_addr, allocator);
	}

	template <typename Allocator>
	static void fill_upload_reply(const elliptics::sync_write_result &result,
			rapidjson::Value &result_object, Allocator &allocator) {
		rapidjson::Value infos;
		infos.SetArray();

		for (auto it = result.begin(); it != result.end(); ++it) {
			rapidjson::Value download_info;
			download_info.SetObject();

			fill_upload_reply(*it, download_info, allocator);

			infos.PushBack(download_info, allocator);
		}

		result_object.AddMember("info", infos, allocator);
	}
};

template <typename Server, typename Stream>
class on_upload_base : public thevoid::buffered_request_stream<Server>, public std::enable_shared_from_this<Stream> {
public:
	virtual void on_request(const thevoid::http_request &req) {
		m_timer.restart();

		this->set_chunk_size(10 * 1024 * 1024);

		try {
			const auto &query = this->request().url().query();
			m_orig_offset = m_offset = query.item_value("offset", 0llu);
			m_key_orig = url::key(req, false);
			m_key = this->set_key(m_key_orig);
		} catch (const std::exception &e) {
			NLOG_ERROR("buffered-write: url: %s: invalid offset parameter: %s",
					req.url().to_human_readable().c_str(), e.what());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (auto size = req.headers().content_length())
			m_size = *size;
		else
			m_size = 0;

		elliptics::error_info err = this->server()->bucket_processor()->get_bucket(m_size, m_bucket);
		if (err) {
			NLOG_ERROR("buffered-write: on_request: url: %s: could not find bucket for size: %ld: %s [%d]",
					req.url().to_human_readable().c_str(), m_size, err.message().c_str(), err.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		auto content_type = req.headers().content_type();
		if (content_type) {
			const auto &ct = content_type.get();
			if (ct.substr(0, 10) == "multipart/") {
				err = multipart_init(ct);
				if (err) {
					NLOG_ERROR("buffered-write: on_request: url: %s: could not initialize multipart: "
							"content_type: %s, error: %s [%d]",
							req.url().to_human_readable().c_str(), ct.c_str(),
							err.message().c_str(), err.code());

					this->send_reply(swarm::http_response::bad_request);
					return;
				}
			}
		}

		NLOG_INFO("buffered-write: on_request: url: %s, bucket: %s, key: %s, offset: %llu, size: %llu, multipart: %s",
				this->request().url().to_human_readable().c_str(),
				m_bucket->name().c_str(), m_key.to_string().c_str(),
				(unsigned long long)m_offset, (unsigned long long)m_size,
				m_multipart_check ? m_multipart_boundary.c_str() : "disabled");

		m_session.reset(new elliptics::session(m_bucket->session()));
		this->try_next_chunk();
	}

	virtual void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
		const auto data = create_data(buffer);

		NLOG_INFO("buffered-write: on_chunk: url: %s, size: %zu, m_offset: %lu, flags: %u",
				this->request().url().to_human_readable().c_str(), data.size(), m_offset, flags);

		if (m_multipart_check) {
			m_current_flags = flags;
			m_multipart_current_chunk = elliptics::data_pointer::allocate(data.size());
			m_multipart_current_offset = 0;

			size_t fed = 0;
			do {
				size_t ret = m_multipart.feed(data.data<char>() + fed, data.size() - fed);
				fed += ret;

				NLOG_NOTICE("fed: %ld, ret: %ld, data.size: %ld, stopped: %d, has_error: %d",
						fed, ret, data.size(), m_multipart.stopped(), m_multipart.hasError());
			} while (fed < data.size() && !m_multipart.stopped());

			if (m_multipart.hasError()) {
				NLOG_ERROR("buffered-write: on_chunk: url: %s, size: %zu, m_offset: %lu, flags: %u, "
						"invalid multipart message: %s, fed: %ld, boundary: %s",
						this->request().url().to_human_readable().c_str(),
						data.size(), m_offset, flags, m_multipart.getErrorMessage(), fed,
						m_multipart_boundary.c_str());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}

			if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
				// this is the last message from client and multipart parser has not found end of the stream,
				// complete multipart state machine anyway
				if (m_multipart_current_offset) {
					this->on_part_end();
				}
			}

			return;
		}

		on_chunk_raw(data, flags);
	}

	virtual void on_chunk_raw(const elliptics::data_pointer &data, unsigned int flags) {
		NLOG_INFO("buffered-write: on_upload_base::on_chunk_raw: url: %s, size: %zu, m_offset: %lu, flags: %u",
				this->request().url().to_human_readable().c_str(), data.size(), m_offset, flags);

		elliptics::async_write_result result = write(data, flags);
		m_offset += data.size();

		if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
			result.connect(std::bind(&on_upload_base::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		} else {
			result.connect(std::bind(&on_upload_base::on_write_partial, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		}
	}

	elliptics::async_write_result write(const elliptics::data_pointer &data, unsigned int flags) {
		if (flags == thevoid::buffered_request_stream<Server>::single_chunk) {
			NLOG_INFO("buffered-write: write-data-single-chunk: url: %s, offset: %lu, size: %zu",
					this->request().url().to_human_readable().c_str(), m_offset, data.size());
			return m_session->write_data(m_key, data, m_offset);
		} else if (m_size > 0) {
			if (flags & thevoid::buffered_request_stream<Server>::first_chunk) {
				NLOG_INFO("buffered-write: prepare: url: %s, offset: %lu, size: %lu",
						this->request().url().to_human_readable().c_str(), m_offset, m_size);
				return m_session->write_prepare(m_key, data, m_offset, m_offset + m_size);
			} else if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
				NLOG_INFO("buffered-write: commit: url: %s, offset: %lu, size: %lu",
						this->request().url().to_human_readable().c_str(), m_offset, m_offset + data.size());
				return m_session->write_commit(m_key, data, m_offset, m_offset + data.size());
			} else {
				NLOG_INFO("buffered-write: plain: url: %s, offset: %lu, size: %zu",
						this->request().url().to_human_readable().c_str(), m_offset, data.size());
				return m_session->write_plain(m_key, data, m_offset);
			}
		} else {
			NLOG_INFO("buffered-write: write-data: url: %s, offset: %lu, size: %zu",
					this->request().url().to_human_readable().c_str(), m_offset, data.size());
			return m_session->write_data(m_key, data, m_offset);
		}
	}

	virtual void on_error(const boost::system::error_code &error) {
		NLOG_ERROR("buffered-write: on_error: url: %s, error: %s, written: %zu/%zu, time: %ld msecs",
				this->request().url().to_human_readable().c_str(), error.message().c_str(),
				m_offset - m_orig_offset, m_size, m_timer.elapsed());
	}

	virtual std::string set_key(const std::string &key) {
		return key;
	}

protected:
	elliptics::key m_key;
	std::string m_key_orig;
	ebucket::bucket m_bucket;
	std::unique_ptr<elliptics::session> m_session;

	uint64_t m_offset, m_orig_offset;
	uint64_t m_size;

	ribosome::timer m_timer;

	MultipartReader m_multipart;
	bool m_multipart_check = false;
	std::string m_multipart_boundary;

	elliptics::data_pointer m_multipart_current_chunk;
	size_t m_multipart_current_offset = 0;
	unsigned int m_current_flags = 0;

	elliptics::error_info multipart_init(const std::string &ct) {
		std::vector<std::string> attrs;
		boost::split(attrs, ct, boost::is_any_of(";"));
		for (auto &attr: attrs) {
			boost::trim(attr);
			if (attr.size() <= 1)
				continue;

			auto eqpos = attr.find('=');
			if (eqpos == std::string::npos)
				continue;

			if (attr.substr(0, eqpos) != "boundary")
				continue;

			std::string b = attr.substr(eqpos+1);
			if (b.empty()) {
				return elliptics::create_error(-EINVAL, "invalid empty boundary, header: '%s'", ct.c_str());
			}

			m_multipart_boundary = b;
			m_multipart.setBoundary(b);
			m_multipart.userData = (void *)this;
			m_multipart.onPartBegin = &this->on_part_begin_c;
			m_multipart.onPartData = &this->on_part_data_c;
			m_multipart.onPartEnd = &this->on_part_end_c;

			m_multipart_check = true;

			NLOG_NOTICE("buffered-write: mutlipart_init: url: %s, content-type: '%s', boundary: '%s'",
				this->request().url().to_human_readable().c_str(), ct.c_str(), m_multipart_boundary.c_str());
			return elliptics::error_info();
		}

		return elliptics::create_error(-EINVAL, "could not find valid boundary, header: '%s'", ct.c_str());
	}

	void on_part_begin(const MultipartHeaders &headers) {
		for (auto it = headers.begin(), end = headers.end(); it != end; ++it) {
			if (it->first != "Content-Disposition")
				continue;

			std::vector<std::string> attrs;
			boost::split(attrs, it->second, boost::is_any_of(";"));
			for (auto &attr: attrs) {
				boost::trim(attr);
				if (attr.size() <= 1)
					continue;

				auto eqpos = attr.find('=');
				if (eqpos == std::string::npos)
					continue;

				if (attr.substr(0, eqpos) != "filename")
					continue;

				eqpos++;
				if (eqpos >= attr.size())
					continue;

				if (attr[eqpos] == '"')
					eqpos++;

				if (eqpos == attr.size())
					continue;

				ssize_t count = attr.size() - eqpos;
				if (attr[attr.size() - 1] == '"')
					count--;

				if (count <= 0)
					continue;

				std::string b = attr.substr(eqpos, count);
				if (b.empty())
					continue;

				NLOG_INFO("buffered-write: on_part_begin: url: %s, "
						"internal multipart header changes filename: %s -> %s",
						this->request().url().to_human_readable().c_str(),
						m_key_orig.c_str(), b.c_str());

				m_key_orig = b;
				m_key = this->set_key(b);
			}
		}
	}

	static void on_part_begin_c(const MultipartHeaders &headers, void *priv) {
		on_upload_base<Server, Stream> *th = reinterpret_cast<on_upload_base<Server, Stream> *>(priv);
		th->on_part_begin(headers);
	}

	void on_part_data(const char *data, size_t size) {
		if (m_multipart_current_offset + size > m_multipart_current_chunk.size()) {
			elliptics::throw_error(-E2BIG, "invalid multipart message: "
					"current_offset: %ld, chunk_size: %ld, sum %ld must be <= data_pointer_size: %ld",
					m_multipart_current_offset, size,
					m_multipart_current_offset + size, m_multipart_current_chunk.size());
		}

		memcpy(m_multipart_current_chunk.data<char>() + m_multipart_current_offset, data, size);
		m_multipart_current_offset += size;
	}

	static void on_part_data_c(const char *data, size_t size, void *priv) {
		on_upload_base<Server, Stream> *th = reinterpret_cast<on_upload_base<Server, Stream> *>(priv);
		th->on_part_data(data, size);
	}

	void on_part_end() {
		on_chunk_raw(m_multipart_current_chunk.slice(0, m_multipart_current_offset), m_current_flags);
		// clear offset flag, this means chunk has been sent
		m_multipart_current_offset = 0;
	}

	static void on_part_end_c(void *priv) {
		on_upload_base<Server, Stream> *th = reinterpret_cast<on_upload_base<Server, Stream> *>(priv);
		th->on_part_end();
	}

	virtual void on_write_partial(const elliptics::sync_write_result &result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("buffered-write: on_write_partial: url: %s, partial write error: %s, "
					"written: %zu/%zu, time: %ld msecs",
					this->request().url().to_human_readable().c_str(), error.message().c_str(),
					m_offset - m_orig_offset, m_size, m_timer.elapsed());
			this->on_write_finished(result, error);
			return;
		}

		// continue only with the groups where update succeeded
		std::vector<int> groups, rem_groups;

		std::ostringstream sgroups, egroups;

		for (auto it = result.begin(); it != result.end(); ++it) {
			const elliptics::write_result_entry & entry = *it;

			int group_id = entry.command()->id.group_id;

			if (entry.error()) {
				rem_groups.push_back(group_id);

				if (egroups.tellp() != 0)
					egroups << ":";
				egroups << group_id;
			} else {
				groups.push_back(group_id);

				if (sgroups.tellp() != 0)
					sgroups << ":";
				sgroups << group_id;
			}
		}

		NLOG_INFO("buffered-write: on_write_partial: url: %s: "
				"success-groups: %s, error-groups: %s, offset: %lu, written: %zu/%zu, time: %ld msecs",
				this->request().url().to_human_readable().c_str(), sgroups.str().c_str(), egroups.str().c_str(),
				m_offset, m_offset - m_orig_offset, m_size, m_timer.elapsed());

		elliptics::session tmp = m_session->clone();
		tmp.set_groups(rem_groups);
		tmp.remove(m_key);

		m_session->set_groups(groups);

		this->try_next_chunk();
	}

	void generate_upload_reply(nullx::JsonValue &value, const elliptics::sync_write_result &result) {
		upload_completion::fill_upload_reply(result, value, value.GetAllocator());

		rapidjson::Value sgroups_val(rapidjson::kArrayType);
		rapidjson::Value egroups_val(rapidjson::kArrayType);

		std::ostringstream sgroups, egroups;
		for (auto it = result.begin(); it != result.end(); ++it) {
			const elliptics::write_result_entry & entry = *it;

			int group_id = entry.command()->id.group_id;
			rapidjson::Value group_val(group_id);

			if (entry.error()) {
				if (egroups.tellp() != 0)
					egroups << ":";
				egroups << group_id;
				egroups_val.PushBack(group_val, value.GetAllocator());
			} else {
				if (sgroups.tellp() != 0)
					sgroups << ":";
				sgroups << group_id;
				sgroups_val.PushBack(group_val, value.GetAllocator());
			}
		}

		NLOG_INFO("buffered-write: on_write_finished: url: %s: "
				"success-groups: %s, error-groups: %s, offset: %lu, written: %zu/%zu, time: %ld msecs",
				this->request().url().to_human_readable().c_str(), sgroups.str().c_str(), egroups.str().c_str(),
				m_offset, m_offset - m_orig_offset, m_size, m_timer.elapsed());

		rapidjson::Value bucket_val(m_bucket->name().c_str(), m_bucket->name().size(), value.GetAllocator());
		value.AddMember("bucket", bucket_val, value.GetAllocator());

		rapidjson::Value key_val(m_key_orig.c_str(), m_key_orig.size(), value.GetAllocator());
		value.AddMember("key", key_val, value.GetAllocator());

		value.AddMember("success-groups", sgroups_val, value.GetAllocator());
		value.AddMember("error-groups", egroups_val, value.GetAllocator());
		value.AddMember("offset", m_orig_offset, value.GetAllocator());
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("buffered-write: on_write_finished: url: %s, full write error: %s, "
					"written: %zu/%zu, time: %ld msecs",
					this->request().url().to_human_readable().c_str(), error.message().c_str(),
					m_offset - m_orig_offset, m_size, m_timer.elapsed());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		nullx::JsonValue value;
		generate_upload_reply(value, result);

		std::string data = value.ToString();

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}


};

template <typename Server>
class on_upload : public on_upload_base<Server, on_upload<Server>>
{
public:
};

template <typename Server, typename Stream>
class on_upload_auth_base : public on_upload_base<Server, Stream>
{
public:
	virtual std::string set_key(const std::string &key) {
		return m_mbox.filename(key);
	}

	virtual void on_request(const thevoid::http_request &req) {
		if (!this->server()->check_cookie(req, m_mbox)) {
			NLOG_ERROR("upload: on_request: url: %s: invalid cookie, redirecting to login page",
					req.url().to_human_readable().c_str());
			thevoid::http_response reply;
			reply.headers().set("Access-Control-Allow-Origin", "*");
			reply.set_code(swarm::http_response::forbidden);
			reply.headers().set_content_length(0);
			this->send_reply(std::move(reply));
			return;
		}

		NLOG_INFO("upload: on_request: url: %s: auth succeeded: username: %s, meta_bucket: %s, meta_index: %s",
				req.url().to_human_readable().c_str(),
				m_mbox.username.c_str(), m_mbox.meta_bucket.c_str(), m_mbox.meta_index.c_str());

		on_upload_base<Server, Stream>::on_request(req);
	}

private:
	mailbox_t m_mbox;
};

template <typename Server>
class on_upload_auth : public on_upload_auth_base<Server, on_upload_auth<Server>>
{
};

template <typename Server>
class on_upload_auth_media : public on_upload_auth_base<Server, on_upload_auth_media<Server>>
{
public:
	virtual void on_chunk_raw(const elliptics::data_pointer &dp, unsigned int flags) {
		NLOG_INFO("buffered-write: on_upload_auth_media::on_chunk_raw: url: %s, size: %zu, m_offset: %lu, flags: %u",
				this->request().url().to_human_readable().c_str(), dp.size(), this->m_offset, flags);


		std::string content_type = this->server()->content_type(this->m_key_orig);
		std::string mtype = content_type.substr(0, 6);
		bool new_file = this->m_key_orig != m_key_orig_stored;

		// @m_key_orig contains filename for the new file, if we have another file currently being processed,
		// its name is stored in @m_key_orig_stored
		if (new_file && m_key_orig_stored.empty()) {
			m_key_orig_stored = this->m_key_orig;
		}

		m_current_data = dp;
		m_current_flags = flags;

		if (mtype != "audio/" && mtype != "video/") {
			continue_parent();

			if (new_file) {
				m_key_orig_stored = this->m_key_orig;
			}
			return;
		}

		elliptics::error_info err;
		err = stream_parse(new_file);
		if (err) {
			NLOG_ERROR("on_upload_auth_media::on_chunk_raw: url: %s, key: %s, stream parsing error: %s [%d]",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					err.message().c_str(), err.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		if (new_file) {
			m_key_orig_stored = this->m_key_orig;
		}
	}
private:
	std::string m_key_orig_stored; // currently processed audio/video file
	std::unique_ptr<nulla::iso_stream_fallback_reader> m_iso_reader;
	elliptics::data_pointer m_current_data;
	unsigned int m_current_flags;
	elliptics::sync_write_result m_transcoded_data_result;

	void continue_parent() {
		on_upload_auth_base<Server, on_upload_auth_media<Server>>::on_chunk_raw(m_current_data, m_current_flags);
	}

	void continue_parent_wrapper(const elliptics::sync_write_result &meta_result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("on_upload_auth_media::continue_parent_wrapper: url: %s, key: %s, error: %s [%d]",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					error.message().c_str(), error.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		(void) meta_result;

		NLOG_ERROR("on_upload_auth_media::continue_parent_wrapper: url: %s, key: %s, is_streaming: %d",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					m_iso_reader->is_streaming());

		if (m_iso_reader->is_streaming()) {
			continue_parent();
		} else {
			this->on_write_finished(m_transcoded_data_result, error);
		}
	}

	void store_metadata_elliptics(const std::string &meta) {
		this->m_session->write_data(nulla::metadata_key(this->set_key(m_key_orig_stored)), meta, 0).connect(
				std::bind(&on_upload_auth_media<Server>::continue_parent_wrapper,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

	void dump_meta_info(const std::string &key, const std::string &file, const std::string &meta, const nulla::media &media) {
		NLOG_INFO("on_upload_auth_media::dump_meta_info: key: %s, file: %s, metadata-size: %ld, tracks: %ld",
				key.c_str(), file.c_str(), meta.size(), media.tracks.size());

		size_t idx = 0;
		for (auto it = media.tracks.begin(), it_end = media.tracks.end(); it != it_end; ++it) {
			NLOG_INFO("on_upload_auth_media::dump_meta_info: key: %s, file: %s, track: %ld/%ld: %s",
					key.c_str(), file.c_str(), idx, media.tracks.size(), it->str().c_str());

			++idx;
		}
	}

	void upload_local_file(const std::string &file, const std::string &key) {
		elliptics::key id(this->set_key(key));

		this->m_session->transform(id);

		int err;

		int fd = open(file.c_str(), O_RDONLY | O_LARGEFILE | O_CLOEXEC);
		if (fd < 0) {
			err = -errno;

			NLOG_ERROR("on_upload_auth_media::upload_local_file: url: %s, key: %s, "
					"local_file: %s: can not open local file: [%s] %d",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(), file.c_str(),
					strerror(-err), err);
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		struct stat stat;
		memset(&stat, 0, sizeof(stat));

		err = fstat(fd, &stat);
		if (err) {
			err = -errno;
			NLOG_ERROR("on_upload_auth_media::upload_local_file: url: %s, key: %s, "
					"local_file: %s: can not stat local file: [%s] %d",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(), file.c_str(),
					strerror(-err), err);
			close(fd);
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		dnet_io_control ctl;
		memset(&ctl, 0, sizeof(struct dnet_io_control));

		ctl.data = NULL;
		ctl.fd = fd;
		ctl.local_offset = 0;

		memcpy(ctl.io.id, id.id().id, DNET_ID_SIZE);
		memcpy(ctl.io.parent, id.id().id, DNET_ID_SIZE);

		ctl.io.size = stat.st_size;
		ctl.io.offset = 0;
		ctl.io.timestamp.tsec = stat.st_mtime;
		ctl.io.timestamp.tnsec = 0;
		ctl.id = id.id();

		this->m_session->write_data(ctl).connect(std::bind(&on_upload_auth_media<Server>::file_uploaded_store_metadata,
				this->shared_from_this(), file, fd, std::placeholders::_1, std::placeholders::_2));

	}

	void file_uploaded_store_metadata(std::string &output_file, int fd,
			const elliptics::sync_write_result &result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("on_upload_auth_media::file_uploaded_store_metadata: url: %s, key: %s, error: %s [%d]",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					error.message().c_str(), error.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		m_transcoded_data_result = result;

		// XXX remove output file
		close(fd);

		try {
			std::string meta;
			nulla::iso_reader reader(output_file.c_str());
			reader.parse();

			meta = reader.pack();
			const nulla::media &media = reader.get_media();

			// this should not happen
			if (meta.empty()) {
				throw std::runtime_error("empty metadata file");
			}

			dump_meta_info(m_key_orig_stored, output_file, meta, media);
			store_metadata_elliptics(meta);
		} catch (const std::exception &e) {
			NLOG_ERROR("on_upload_auth_media::continue_parent_transcoding_wrapper: url: %s, key: %s, "
					"could not parse ISO file %s: %s",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					output_file.c_str(), e.what());

			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}
	}

	void continue_parent_transcoding_wrapper(const std::string &input_file,
			const std::string &output_file, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("on_upload_auth_media::continue_parent_transcoding_wrapper: url: %s, key: %s, error: %s [%d]",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					error.message().c_str(), error.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		NLOG_INFO("on_upload_auth_media::continue_parent_transcoding_wrapper: url: %s, key: %s, local file: %s -> %s",
					this->request().url().to_human_readable().c_str(),
					this->m_key_orig.c_str(),
					input_file.c_str(), output_file.c_str());

		remove(input_file.c_str());
		upload_local_file(output_file, this->m_key_orig);
	}

	elliptics::error_info stream_parse(bool new_file) {
		try {
			if (new_file) {
				if (m_iso_reader) {
					store_metadata_or_transcode(m_iso_reader->is_streaming());
				}

				m_iso_reader.reset(new nulla::iso_stream_fallback_reader(this->server()->tmp_dir(),
							m_current_data.data<char>(), m_current_data.size()));
				m_iso_reader->do_not_remove();
			} else {
				m_iso_reader->feed(m_current_data.data<char>(), m_current_data.size());
			}

			// if it is the last chunk, store media metadata and postpone higher layer invocation,
			// if it is not the last chunk, just call the upper layer which will store data into elliptics
			if (m_current_flags & thevoid::buffered_request_stream<Server>::last_chunk) {
				// If this is ISO file, then we have already uploaded its content into the storage
				//
				// If this file is either not ISO and has to be transcoded,
				// or it is not very suitable for streaming (but still ISO format),
				// which is ok for Nulla stream server
				// in this case we just have to upload it and then store metadata
				store_metadata_or_transcode(m_iso_reader->is_streaming());
			} else {
				if (m_iso_reader->is_streaming()) {
					continue_parent();
				} else {
					// we do not upload file if it failed to read its metadata,
					// since it will be transcoded later and if transcoding fails,
					// we do not want this file in the storage. If transcoding will succeed,
					// file will be uploaded but with different name.
					this->try_next_chunk();
				}
			}

		} catch (const std::exception &e) {
			NLOG_ERROR("on_upload_auth_media::stream_parse: url: %s, key: %s, error: %s",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(), e.what());
			return elliptics::create_error(-EINVAL, "stream_parse: key: %s, error: %s", this->m_key_orig.c_str(), e.what());
		}

		return elliptics::error_info();
	}

	void store_metadata_or_transcode(bool is_streaming) {
		std::string meta;

		try {
			meta = m_iso_reader->pack();
			const nulla::media &media = m_iso_reader->get_media();

			dump_meta_info(m_key_orig_stored, is_streaming ? "streaming" : m_iso_reader->tmp_file(), meta, media);
		} catch (const std::exception &e) {
			NLOG_ERROR("on_upload_auth_media::store_metadata: url: %s, key: %s, "
					"tmp_file: %s, error: %s",
					this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(),
					m_iso_reader->tmp_file().c_str(), e.what());
		}

		if (meta.empty()) {
			schedule_transcoding(m_iso_reader->tmp_file());
		} else {
			if (is_streaming) {
				store_metadata_elliptics(meta);
			} else {
				upload_local_file(m_iso_reader->tmp_file(), m_key_orig_stored);
			}
		}
	}

	void schedule_transcoding(const std::string &input_file) {
		NLOG_INFO("on_upload_auth_media::schedule_transcoding: url: %s, key: %s, input_file: %s",
				this->request().url().to_human_readable().c_str(), this->m_key_orig.c_str(), input_file.c_str());

		this->server()->schedule_transcoding(input_file,
				std::bind(&on_upload_auth_media<Server>::continue_parent_transcoding_wrapper,
					this->shared_from_this(), input_file,
					std::placeholders::_1, std::placeholders::_2));
	}
};

}} // namespace ioremap::nullx
