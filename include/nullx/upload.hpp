#pragma once

#include "nullx/asio.hpp"
#include "nullx/jsonvalue.hpp"
#include "nullx/log.hpp"
#include "nullx/url.hpp"

#include <swarm/url.hpp>

#include <elliptics/session.hpp>
#include <elliptics/interface.h>

#include <ribosome/file.hpp>
#include <ribosome/timer.hpp>

#include <nulla/iso_reader.hpp>
#include <nulla/utils.hpp>

namespace ioremap { namespace nullx {

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
		result_object.AddMember("offset-within-data-file", entry.file_info()->offset, allocator);

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
class on_transcode_base : public thevoid::buffered_request_stream<Server>, public std::enable_shared_from_this<Stream> {
public:
	virtual ~on_transcode_base() {
		if (m_fd >= 0) {
			close(m_fd);
		}

		if (m_input_file.size()) {
			remove(m_input_file.c_str());
		}

		if (m_output_file.size()) {
			remove(m_output_file.c_str());
		}
	}

	virtual void on_request(const thevoid::http_request &req) {
		m_timer.restart();
		this->set_chunk_size(10 * 1024 * 1024);

		auto &headers = req.headers();
		auto egroups = headers.get("X-Ell-Groups");
		if (egroups) {
			m_groups = elliptics::parse_groups(egroups->c_str());

			auto eid = headers.get("X-Ell-ID");
			if (eid) {
				dnet_raw_id id;

				int err = dnet_parse_numeric_id(eid->c_str(), id.id);
				if (!err) {
					m_elliptics_key.reset(new elliptics::key(id));
				}
			}
			auto ekey = headers.get("X-Ell-Key");
			if (ekey) {
				m_elliptics_key.reset(new elliptics::key(ekey->c_str()));

				const auto ebucket = headers.get("X-Ell-Bucket");
				if (ebucket) {
					m_bucket = *ebucket;
				}
			}

			auto mgroups = headers.get("X-Ell-Metadata-Groups");
			if (mgroups) {
				m_metadata_groups = elliptics::parse_groups(mgroups->c_str());

				auto mid = headers.get("X-Ell-Metadata-ID");
				if (mid) {
					dnet_raw_id id;

					int err = dnet_parse_numeric_id(mid->c_str(), id.id);
					if (!err) {
						m_elliptics_metadata_key.reset(new elliptics::key(id));
					}
				}
				auto mkey = headers.get("X-Ell-Metadata-Key");
				if (mkey) {
					m_elliptics_metadata_key.reset(new elliptics::key(mkey->c_str()));

					auto mbucket = headers.get("X-Ell-Metadata-Bucket");
					if (mbucket) {
						m_metadata_bucket = *mbucket;
					}
				}
			}
		}

		static const std::string secure_xxx = "/XXXXXXXX";
		m_input_file = this->server()->tmp_dir() + secure_xxx;

		int err = mkstemp((char *)m_input_file.c_str());
		if (err < 0) {
			err = -errno;
			NLOG_ERROR("transcode: on_request: could not create temporary file, template: %s, error: %s [%d]",
					m_input_file.c_str(), strerror(-err), err);
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		m_fd = err;
		NLOG_INFO("transcode: on_request: tmp_file: %s", m_input_file.c_str());

		this->try_next_chunk();
	}

	virtual void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
		size_t size = boost::asio::buffer_size(buffer);
		ssize_t err = ::write(m_fd, boost::asio::buffer_cast<const char*>(buffer), size);
		if (err != (ssize_t)size) {
			NLOG_ERROR("transcode: on_chunk: could not write data, file: %s, offset: %ld, size: %ld, error: %s [%ld]",
					m_input_file.c_str(), m_input_size, size, strerror(-err), err);
			this->send_reply(swarm::http_response::service_unavailable);
		}

		m_input_size += err;

		if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
			close(m_fd);
			m_fd = -1;

			schedule_transcoding();
		} else {
			this->try_next_chunk();
		}
	}

	virtual void on_error(const boost::system::error_code &error) {
		NLOG_ERROR("transcode: on_error: error: %s", error.message().c_str());
	}


protected:
	int m_fd = -1;
	std::string m_input_file;
	std::string m_output_file;
	size_t m_input_size = 0;
	size_t m_output_size = 0;

	ribosome::timer m_timer;

	// if there are X-Ell-Groups and X-Ell-Key (+ optionally X-Ell-Bucket) or X-Ell-ID headers,
	// transcoded file has to be written into given groups using provoided bucket/key or id
	std::unique_ptr<elliptics::key> m_elliptics_key;
	std::string m_bucket;
	std::vector<int> m_groups;

	// if there are headers like above but with 'Metadata' suffix (like X-Ell-Metadata-Key),
	// then ISO metadata will also be uploaded into elliptics
	std::unique_ptr<elliptics::key> m_elliptics_metadata_key;
	std::string m_metadata_bucket;
	std::vector<int> m_metadata_groups;

	std::unique_ptr<ribosome::mapped_file> m_file;

	void generate_upload_reply(nullx::JsonValue &value, const elliptics::sync_write_result &result) {
		upload_completion::fill_upload_reply(result, value, value.GetAllocator());

		rapidjson::Value sgroups_val(rapidjson::kArrayType);
		rapidjson::Value egroups_val(rapidjson::kArrayType);

		std::ostringstream sgroups, egroups;
		for (auto it = result.begin(); it != result.end(); ++it) {
			const elliptics::write_result_entry &entry = *it;

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

		NLOG_INFO("transcode: generate_upload_reply: transcoded: %s -> %s, size: %ld -> %ld, "
				"success-groups: %s, error-groups: %s, time: %ld msecs",
				m_input_file.c_str(), m_output_file.c_str(), m_input_size, m_output_size,
				sgroups.str().c_str(), egroups.str().c_str(),
				m_timer.elapsed());

		if (m_elliptics_key->by_id()) {
			std::string id = m_elliptics_key->to_string();

			rapidjson::Value id_val(id.c_str(), id.size(), value.GetAllocator());
			value.AddMember("id", id_val, value.GetAllocator());
		} else {
			rapidjson::Value bucket_val(m_bucket.c_str(), m_bucket.size(), value.GetAllocator());
			value.AddMember("bucket", bucket_val, value.GetAllocator());

			std::string key = m_elliptics_key->to_string();

			rapidjson::Value key_val(key.c_str(), key.size(), value.GetAllocator());
			value.AddMember("key", key_val, value.GetAllocator());
		}

		value.AddMember("success-groups", sgroups_val, value.GetAllocator());
		value.AddMember("error-groups", egroups_val, value.GetAllocator());
	}

	std::string print_key(bool meta) {
		if (meta) {
			if (m_elliptics_metadata_key->by_id()) {
				return m_elliptics_metadata_key->to_string();
			} else {
				return m_metadata_bucket + "/" + m_elliptics_metadata_key->to_string();
			}
		} else {
			if (m_elliptics_key->by_id()) {
				return m_elliptics_key->to_string();
			} else {
				return m_bucket + "/" + m_elliptics_key->to_string();
			}
		}
	}

	void elliptics_send_reply(const elliptics::sync_write_result &result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("transcode: elliptics_send_reply: file: %s, key: %s, metadata_key: %s, error: %s [%d]",
					m_output_file.c_str(), print_key(false).c_str(), print_key(true).c_str(),
					error.message().c_str(), error.code());

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

	void store_metadata_elliptics(const std::string &meta) {
		elliptics::key id(*m_elliptics_metadata_key);
		elliptics::session session(this->server()->session());
		session.transform(id);
		session.set_groups(m_metadata_groups);
		session.write_data(id, meta, 0).connect(std::bind(&on_transcode_base::elliptics_send_reply,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

	void dump_meta_info(const std::string &file, const std::string &meta, const nulla::media &media) {
		NLOG_INFO("transcode: dump_meta_info: file: %s, metadata-size: %ld, tracks: %ld",
				file.c_str(), meta.size(), media.tracks.size());

		size_t idx = 0;
		for (auto it = media.tracks.begin(), it_end = media.tracks.end(); it != it_end; ++it) {
			NLOG_INFO("transcode: dump_meta_info: file: %s, track: %ld/%ld: %s",
					file.c_str(), idx, media.tracks.size(), it->str().c_str());

			++idx;
		}
	}

	void upload_local_file() {
		elliptics::key id(*m_elliptics_key);

		elliptics::session session(this->server()->session());
		session.transform(id);
		session.set_groups(m_groups);

		int err;

		int fd = open(m_output_file.c_str(), O_RDONLY | O_LARGEFILE | O_CLOEXEC);
		if (fd < 0) {
			err = -errno;

			NLOG_ERROR("transcode: upload_local_file: could not open local file, file: %s, error: [%s] %d",
					m_output_file.c_str(), strerror(-err), err);
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		struct stat stat;
		memset(&stat, 0, sizeof(stat));

		err = fstat(fd, &stat);
		if (err) {
			err = -errno;
			NLOG_ERROR("transcode: upload_local_file: could not stat local file, file: %s, error: [%s] %d",
					m_output_file.c_str(), strerror(-err), err);

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

		ctl.io.size = m_output_size = stat.st_size;
		ctl.io.offset = 0;
		ctl.io.timestamp.tsec = stat.st_mtime;
		ctl.io.timestamp.tnsec = 0;
		ctl.id = id.id();

		session.write_data(ctl).connect(std::bind(&on_transcode_base::file_uploaded,
				this->shared_from_this(), fd, std::placeholders::_1, std::placeholders::_2));

	}

	void file_uploaded(int fd, const elliptics::sync_write_result &result, const elliptics::error_info &error) {
		// closing output file after it has been uploaded
		close(fd);

		if (error) {
			NLOG_ERROR("transcode: file_uploaded: could not upload transcoded file into elliptics, "
					"file: %s, error: %s [%d]",
					m_output_file.c_str(), error.message().c_str(), error.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		if (m_elliptics_metadata_key) {
			try {
				std::string meta;
				nulla::iso_reader reader(m_output_file.c_str());
				reader.parse();

				meta = reader.pack();
				const nulla::media &media = reader.get_media();

				// this should not happen, since we transcode exactly into format supported by ISO reader
				if (meta.empty()) {
					throw std::runtime_error("empty metadata file");
				}

				dump_meta_info(m_output_file, meta, media);

				store_metadata_elliptics(meta);
			} catch (const std::exception &e) {
				NLOG_ERROR("transcode: file_uploaded: ISO processing exception, file: %s, error: %s",
						m_output_file.c_str(), e.what());

				this->send_reply(swarm::http_response::service_unavailable);
				return;
			}
		} else {
			elliptics_send_reply(result, error);
		}
	}

	void send_transcoded_file_reply() {
		m_file.reset(new ribosome::mapped_file());

		int err = m_file->open(m_output_file.c_str(), O_RDONLY, 0644);
		if (err) {
			NLOG_ERROR("transcode: send_transcoded_file_reply: could not open transcoded, file: %s, error: %s [%d]",
					m_output_file.c_str(), strerror(-err), err);
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		NLOG_INFO("transcode: send_transcoded_file_reply: sending transcoded file back, file: %s, size: %ld",
					m_output_file.c_str(), m_file->size());

		boost::asio::const_buffer buffer(m_file->data(), m_file->size());
		this->send_data(std::move(buffer), std::bind(&on_transcode_base::close, this->shared_from_this(), std::placeholders::_1));
	}

	void transconding_completed(const std::string &output_file, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("transcode: transcoding_completed: transcoding failed, file: %s, error: %s [%d]",
					m_input_file.c_str(), error.message().c_str(), error.code());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		m_output_file = output_file;

		NLOG_INFO("transcode: transcoding_completed: file: %s -> %s", m_input_file.c_str(), m_output_file.c_str());

		if (m_elliptics_key) {
			upload_local_file();
		} else {
			send_transcoded_file_reply();
		}
	}

	void schedule_transcoding() {
		NLOG_NOTICE("transcode: schedule_transcoding: input_file: %s, size: %ld", m_input_file.c_str(), m_input_size);

		this->server()->schedule_transcoding(m_input_file,
				std::bind(&on_transcode_base::transconding_completed,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}
};

template <typename Server>
class on_transcode : public on_transcode_base<Server, on_transcode<Server>>
{
public:
};


}} // namespace ioremap::nullx
