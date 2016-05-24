#pragma once

#include "nullx/auth.hpp"
#include "nullx/upload.hpp"

#include <ribosome/vector_lock.hpp>
#include <greylock/index.hpp>

namespace ioremap { namespace nullx {

template <typename Server, typename Stream>
class on_index_base: public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		if (!this->server()->check_cookie(req, m_mbox)) {
			NLOG_ERROR("index: on_request: url: %s: invalid cookie, redirecting to login page",
					req.url().to_human_readable().c_str());
			thevoid::http_response reply;
			reply.headers().set("Access-Control-Allow-Origin", "*");
			reply.set_code(swarm::http_response::forbidden);
			reply.headers().set_content_length(0);
			this->send_reply(std::move(reply));
			return;
		}

		NLOG_INFO("index: on_request: url: %s: auth succeeded: username: %s, meta_bucket: %s, meta_index: %s",
				req.url().to_human_readable().c_str(),
				m_mbox.username.c_str(), m_mbox.meta_bucket.c_str(), m_mbox.meta_index.c_str());

		std::string data(const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)), boost::asio::buffer_size(buffer));
		rapidjson::Document doc;
		doc.Parse<0>(data.c_str());

		if (doc.HasParseError()) {
			NLOG_ERROR("index: on_request: url: %s: could not parse document: %s, error offset: %zd, data: %s",
					req.url().to_human_readable().c_str(),
					doc.GetParseError(), doc.GetErrorOffset(), data.c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (!doc.IsObject()) {
			NLOG_ERROR("index: on_request: url: %s: document must be object, its type: %d",
					req.url().to_human_readable().c_str(), doc.GetType());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		const rapidjson::Value &files = ebucket::get_array(doc, "files");
		if (!files.IsArray()) {
			NLOG_ERROR("index: on_request: url: %s: document must contain 'files' array",
					req.url().to_human_readable().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		nullx::JsonValue value;
		rapidjson::Value fvals;
		fvals.SetArray();

		int num_indexes_updated = 0;
		for (auto it = files.Begin(), end=files.End(); it != end; it++) {
			if (!it->IsObject()) {
				NLOG_ERROR("index: on_request: url: %s: invalid json, 'files' must contain objects",
						this->request().url().to_human_readable().c_str());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}

			rapidjson::Value fval;
			fval.SetObject();
			auto err = update_file_indexes(*it, fval, value.GetAllocator());
			if (err) {
				NLOG_ERROR("index: on_request: url: %s: username: %s, meta_bucket: %s, meta_index: %s: "
						"index update error: %s [%d]",
						this->request().url().to_human_readable().c_str(),
						m_mbox.username.c_str(), m_mbox.meta_bucket.c_str(), m_mbox.meta_index.c_str(),
						err.message().c_str(), err.code());

				if (err.code() == -EINVAL)
					this->send_reply(swarm::http_response::bad_request);
				else
					this->send_reply(swarm::http_response::internal_server_error);
				return;
			}

			fvals.PushBack(fval, value.GetAllocator());
			++num_indexes_updated;
		}

		value.AddMember("files", fvals, value.GetAllocator());

		NLOG_INFO("index: on_request: url: %s: indexes updated, username: %s, meta_bucket: %s, meta_index: %s, indexes_updated: %d",
				this->request().url().to_human_readable().c_str(),
				m_mbox.username.c_str(), m_mbox.meta_bucket.c_str(), m_mbox.meta_index.c_str(),
				num_indexes_updated);

		std::string reply_data = value.ToString();

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(reply_data.size());

		this->send_reply(std::move(reply), std::move(reply_data));
	}

private:
	mailbox_t m_mbox;

	void timestamp(const std::chrono::time_point<std::chrono::system_clock> &time, uint64_t *tsec, uint64_t *tnsec) const {
		auto sec = std::chrono::time_point_cast<std::chrono::seconds>(time);

		*tsec = std::chrono::system_clock::to_time_t(sec);
		*tnsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time - sec).count();
	}

	template <typename Allocator>
	elliptics::error_info update_file_indexes(const rapidjson::Value &file, rapidjson::Value &reply, Allocator &allocator) {
		const char *kstr = ebucket::get_string(file, "key");
		if (!kstr) {
			return elliptics::create_error(-EINVAL, "file object must contain 'key' string");
		}
		std::string key(kstr);

		const char *bstr = ebucket::get_string(file, "bucket");
		if (!bstr) {
			return elliptics::create_error(-EINVAL, "file object must contain 'bucket' string");
		}
		std::string bucket(bstr);

		const auto &tags = ebucket::get_array(file, "tags");
		if (!tags.IsArray()) {
			return elliptics::create_error(-EINVAL, "file object must contain 'tags' array");
		}

		std::vector<std::string> indexes;
		for (auto it = tags.Begin(), end = tags.End(); it != end; it++) {
			if (!it->IsString()) {
				return elliptics::create_error(-EINVAL, "'tags' array must contain strings");
			}

			indexes.push_back(std::string(it->GetString()));
		}

		auto now = std::chrono::system_clock::now();
		time_t tt = std::chrono::system_clock::to_time_t(now);
		struct tm tm;
		localtime_r((time_t *)&tt, &tm);
		char time_str[128];
		strftime(time_str, sizeof(time_str), "%Y-%m-%d", &tm);
		std::string time_index(time_str);

		indexes.push_back(time_index);

		auto err = update_indexes(bucket, key, m_mbox.meta_bucket, m_mbox.meta_index, indexes);
		if (err)
			return err;

		rapidjson::Value irep;
		irep.SetArray();

		for (auto &idx: indexes) {
			rapidjson::Value ival(idx.c_str(), idx.size(), allocator);
			irep.PushBack(ival, allocator);
		}

		reply.AddMember("indexes", irep, allocator);

		rapidjson::Value kval(key.c_str(), key.size(), allocator);
		reply.AddMember("key", kval, allocator);

		rapidjson::Value bval(bucket.c_str(), bucket.size(), allocator);
		reply.AddMember("bucket", bval, allocator);

		return err;
	}

	elliptics::error_info update_indexes(const std::string &bucket, const std::string &key,
			const std::string meta_bucket, const std::string &meta_index,
			const std::vector<std::string> &indexes) {
		uint64_t tsec, tnsec;
		timestamp(std::chrono::system_clock::now(), &tsec, &tnsec);

		greylock::eurl idx;
		idx.bucket = meta_bucket;

		for (const auto &iname: indexes) {
			greylock::key obj;

			// store filename into every index
			obj.id = key;
			obj.set_timestamp(tsec, tnsec);
			obj.url.bucket = bucket;
			obj.url.key = key;

			idx.key = m_mbox.index(iname);

			ribosome::locker<Server> l(this->server(), idx.str());
			std::unique_lock<ribosome::locker<Server>> lk(l);

			auto err = insert_index(idx, obj);
			if (err)
				return err;
		}

		idx.key = m_mbox.index(meta_index);

		ribosome::locker<Server> l(this->server(), idx.str());
		std::unique_lock<ribosome::locker<Server>> lk(l);

		for (const auto &iname: indexes) {
			greylock::key obj;

			// store index name into meta_index
			obj.id = iname;
			obj.set_timestamp(tsec, tnsec);
			obj.url.bucket = meta_bucket;
			obj.url.key = iname;

			auto err = insert_index(idx, obj);
			if (err)
				return err;
		}

		return elliptics::error_info();
	}

	elliptics::error_info insert_index(const greylock::eurl &idx, const greylock::key &obj) {
		ribosome::timer tm;

		NLOG_NOTICE("insert_index: updating index: %s, obj: %s",
				idx.str().c_str(), obj.str().c_str());
		try {
			greylock::read_write_index index(*this->server()->bucket_processor(), idx);

			NLOG_NOTICE("insert_index: inserting index: %s, obj: %s",
					idx.str().c_str(), obj.str().c_str());
			elliptics::error_info err = index.insert(obj);
			if (err) {
				return elliptics::create_error(err.code(), "insert_index: "
						"index: %s, obj: %s: could not insert new key: %s [%d]",
							idx.str().c_str(), obj.str().c_str(), err.message().c_str(), err.code());
			}
		} catch (const std::exception &e) {
			return elliptics::create_error(-EINVAL, "insert_index: "
					"index: %s, obj: %s: could not insert new key, exception: %s",
						idx.str().c_str(), obj.str().c_str(), e.what());
		}

		NLOG_INFO("insert_index: index: %s, obj: %s, elapsed-time: %ld ms",
				idx.str().c_str(), obj.str().c_str(), tm.restart());
		return elliptics::error_info();
	}

};

template <typename Server>
class on_index : public on_index_base<Server, on_index<Server>>
{
public:
};

template <typename Server, typename Stream>
class on_list_base: public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		if (!this->server()->check_cookie(req, m_mbox)) {
			NLOG_ERROR("list: on_request: url: %s: invalid cookie, redirecting to login page",
					req.url().to_human_readable().c_str());
			thevoid::http_response reply;
			reply.headers().set("Access-Control-Allow-Origin", "*");
			reply.set_code(swarm::http_response::forbidden);
			reply.headers().set_content_length(0);
			this->send_reply(std::move(reply));
			return;
		}

		NLOG_INFO("list: on_request: url: %s: auth succeeded: username: %s, meta_bucket: %s, meta_index: %s",
				req.url().to_human_readable().c_str(),
				m_mbox.username.c_str(), m_mbox.meta_bucket.c_str(), m_mbox.meta_index.c_str());

		std::string data(const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)), boost::asio::buffer_size(buffer));
		rapidjson::Document doc;
		doc.Parse<0>(data.c_str());

		if (doc.HasParseError()) {
			NLOG_ERROR("list: on_request: url: %s: could not parse document: %s, error offset: %zd, data: %s",
					req.url().to_human_readable().c_str(),
					doc.GetParseError(), doc.GetErrorOffset(), data.c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (!doc.IsObject()) {
			NLOG_ERROR("list: on_request: url: %s: document must be object, its type: %d",
					req.url().to_human_readable().c_str(), doc.GetType());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		const rapidjson::Value &tags = ebucket::get_array(doc, "tags");
		if (!tags.IsArray()) {
			NLOG_ERROR("index: on_request: url: %s: document must contain 'tags' array",
					req.url().to_human_readable().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		nullx::JsonValue value;
		rapidjson::Value tvals;
		tvals.SetArray();

		std::vector<std::string> tnames;
		for (auto it = tags.Begin(), end = tags.End(); it != end; ++it) {
			if (!it->IsString()) {
				NLOG_ERROR("index: on_request: url: %s: tags array must contain objects",
						req.url().to_human_readable().c_str());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}

			tnames.push_back(it->GetString());
		}

		if (tnames.empty()) {
			tnames.push_back(m_mbox.meta_index);
		}

		read_indexes(tvals, tnames, value.GetAllocator());

		value.AddMember("tags", tvals, value.GetAllocator());

		std::string reply_data = value.ToString();

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(reply_data.size());

		this->send_reply(std::move(reply), std::move(reply_data));
	}

private:
	mailbox_t m_mbox;

	template <typename Allocator>
	void read_indexes(rapidjson::Value &tvals, const std::vector<std::string> &tnames, Allocator &allocator) {
		for (const auto &tag: tnames) {
			rapidjson::Value tval(rapidjson::kObjectType);

			greylock::eurl idx;
			idx.bucket = m_mbox.meta_bucket;
			idx.key = tag;

			rapidjson::Value tname(rapidjson::kObjectType);
			pack_eurl(tname, idx, allocator);
			tval.AddMember("tag", tname, allocator);

			try {
				rapidjson::Value kvals(rapidjson::kArrayType);

				idx.key = m_mbox.index(tag);

				ribosome::locker<Server> l(this->server(), idx.str());
				std::unique_lock<ribosome::locker<Server>> lk(l);

				greylock::read_only_index index(*this->server()->bucket_processor(), idx);

				for (auto it = index.begin(), end = index.end(); it != end; ++it) {
					rapidjson::Value key(rapidjson::kObjectType);

					pack_key(key, *it, allocator);
					kvals.PushBack(key, allocator);
				}

				tval.AddMember("keys", kvals, allocator);
			} catch (const elliptics::error &e) {
				NLOG_ERROR("list: read_indexes: tag: %s, elliptics exception: %s [%d]",
						idx.str().c_str(), e.what(), e.error_code());
				add_error(tval, e.error_code(), e.what(), allocator);
			} catch (const std::exception &e) {
				NLOG_ERROR("list: read_indexes: tag: %s, exception: %s", idx.str().c_str(), e.what());
				add_error(tval, -EINVAL, e.what(), allocator);
			}

			tvals.PushBack(tval, allocator);
		}
	}

	template <typename Allocator>
	void pack_eurl(rapidjson::Value &e, const greylock::eurl &url, Allocator &allocator) {
		rapidjson::Value bval(url.bucket.c_str(), url.bucket.size(), allocator);
		e.AddMember("bucket", bval, allocator);

		rapidjson::Value kval(url.key.c_str(), url.key.size(), allocator);
		e.AddMember("key", kval, allocator);
	}

	template <typename Allocator>
	void pack_key(rapidjson::Value &e, const greylock::key &key, Allocator &allocator) {
		pack_eurl(e, key.url, allocator);

		rapidjson::Value ival(key.id.c_str(), key.id.size(), allocator);
		e.AddMember("id", ival, allocator);

		rapidjson::Value ts(rapidjson::kObjectType);
		long tsec, tnsec;
		key.get_timestamp(tsec, tnsec);
		ts.AddMember("tsec", tsec, allocator);
		ts.AddMember("tnsec", tnsec, allocator);

		e.AddMember("timestamp", ts, allocator);
	}

	template <typename Allocator>
	void add_error(rapidjson::Value &val, int code, const char *message, Allocator &allocator) {
		rapidjson::Value e(rapidjson::kObjectType);

		e.AddMember("code", code, allocator);

		rapidjson::Value m(message, strlen(message), allocator);
		e.AddMember("message", m, allocator);

		val.AddMember("error", e, allocator);
	}
};

template <typename Server>
class on_list : public on_list_base<Server, on_list<Server>>
{
public:
};

}} // namespace ioremap::nullx
