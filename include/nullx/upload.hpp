#pragma once

#include "nullx/asio.hpp"
#include "nullx/jsonvalue.hpp"
#include "nullx/log.hpp"

#include <swarm/url.hpp>

#include <elliptics/session.hpp>
#include <elliptics/interface.h>

#include <ribosome/timer.hpp>

#include <ebucket/bucket.hpp>

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
			m_key = key(req);
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


		NLOG_INFO("buffered-write: on_request: url: %s, bucket: %s, key: %s, offset: %llu, size: %llu",
				this->request().url().to_human_readable().c_str(),
				m_bucket->name().c_str(), m_key.to_string().c_str(),
				(unsigned long long)m_offset, (unsigned long long)m_size);

		m_session.reset(new elliptics::session(m_bucket->session()));
		this->try_next_chunk();
	}

	virtual void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
		const auto data = create_data(buffer);

		NLOG_INFO("buffered-write: on_chunk: url: %s, size: %zu, m_offset: %lu, flags: %u",
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

protected:
	elliptics::key m_key;
	ebucket::bucket m_bucket;
	std::unique_ptr<elliptics::session> m_session;

	uint64_t m_offset, m_orig_offset;
	uint64_t m_size;

	ribosome::timer m_timer;

	std::string key(const swarm::http_request &req) {
		const auto &path = req.url().path_components();

		size_t prefix_size = 1 + path[0].size() + 1;
		return req.url().path().substr(prefix_size);
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

		value.AddMember("success-groups", sgroups_val, value.GetAllocator());
		value.AddMember("error-groups", egroups_val, value.GetAllocator());
		value.AddMember("offset", m_orig_offset, value.GetAllocator());
		value.AddMember("rate", (double)m_size * 1000.0 / (double)m_timer.elapsed(), value.GetAllocator());
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

}} // namespace ioremap::nullx
