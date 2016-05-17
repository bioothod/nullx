#pragma once

#include "nullx/auth.hpp"
#include "nullx/upload.hpp"

#include <ribosome/vector_lock.hpp>
#include <greylock/index.hpp>

namespace ioremap { namespace nullx {

template <typename Server>
class on_upload_update_index : public on_upload_base<Server, on_upload_update_index<Server>>
{
public:
	on_upload_update_index() {}

	virtual void on_headers(thevoid::http_request &&req) {
		if (!this->server()->check_cookie(req, m_mbox)) {
			NLOG_ERROR("upload: url: %s: invalid cookie, redirecting to login page", req.url().to_human_readable().c_str());
			thevoid::http_response reply;
			reply.headers().set("Access-Control-Allow-Origin", "*");
			reply.set_code(swarm::http_response::forbidden);
			reply.headers().set_content_length(0);
			this->send_reply(std::move(reply));
			return;
		}

		NLOG_ERROR("upload: url: %s: auth succeeded: username: %s, meta_bucket: %s, meta_index: %s",
				req.url().to_human_readable().c_str(),
				m_mbox.username.c_str(), m_mbox.meta_bucket.c_str(), m_mbox.meta_index.c_str());
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		if (error) {
			on_upload_base<Server, on_upload_update_index<Server>>::on_write_finished(result, error);
			return;
		}

		// update indexes
		auto err = update_indexes(this->m_bucket->name(), this->m_key.to_string());
		if (err) {
			on_upload_base<Server, on_upload_update_index<Server>>::on_write_finished(result, err);
			return;
		}

		nullx::JsonValue value;
		this->generate_upload_reply(value, result);

		std::string data = value.ToString();

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

private:
	mailbox_t m_mbox;

	void timestamp(const std::chrono::time_point<std::chrono::system_clock> &time, uint64_t *tsec, uint64_t *tnsec) const {
		auto sec = std::chrono::time_point_cast<std::chrono::seconds>(time);

		*tsec = std::chrono::system_clock::to_time_t(sec);
		*tnsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time - sec).count();
	}

	elliptics::error_info update_indexes(const std::string &bucket, const std::string &filename) {
		uint64_t tsec, tnsec;
		timestamp(std::chrono::system_clock::now(), &tsec, &tnsec);

		struct tm tm;
		localtime_r((time_t *)&tsec, &tm);
		char time_str[128];
		strftime(time_str, sizeof(time_str), "%Y-%m-%d", &tm);
		std::string time_index(time_str);

		std::vector<std::string> indexes;
		indexes.push_back(filename);
		indexes.push_back(time_index);


		for (const auto &iname: indexes) {
			greylock::key obj;

			obj.id = filename;
			obj.set_timestamp(tsec, tnsec);
			obj.url.bucket = bucket;
			obj.url.key = filename;

			ribosome::locker<Server> l(this->server(), iname);
			std::unique_lock<ribosome::locker<Server>> lk(l);

			auto err = insert_index(iname, obj);
			if (err)
				return err;
		}

		greylock::key obj;

		obj.id = time_index;
		obj.set_timestamp(tsec, tnsec);
		obj.url.bucket = m_mbox.meta_bucket;
		obj.url.key = time_index;

		ribosome::locker<Server> l(this->server(), m_mbox.meta_index);
		std::unique_lock<ribosome::locker<Server>> lk(l);

		auto err = insert_index(m_mbox.meta_index, obj);
		if (err)
			return err;

		return elliptics::error_info();
	}

	elliptics::error_info insert_index(const std::string &iname, const greylock::key &obj) {
		ribosome::timer tm;

		try {
			greylock::eurl idx;

			idx.bucket = m_mbox.meta_bucket;
			idx.key = iname;

			greylock::read_write_index index(*this->server()->bucket_processor(), idx);

			elliptics::error_info err = index.insert(obj);
			if (err) {
				return elliptics::create_error(err.code(), "insert_index: "
						"index: %s, obj: %s: could not insert new key: %s [%d]",
					iname.c_str(), obj.str().c_str(), err.message().c_str(), err.code());
			}
		} catch (const std::exception &e) {
			return elliptics::create_error(-EINVAL, "insert_index: "
					"index: %s, obj: %s: could not insert new key, exception: %s",
				iname.c_str(), obj.str().c_str(), e.what());
		}

		NLOG_INFO("insert_index: index: %s, obj: %s, elapsed-time: %ld ms",
				iname.c_str(), obj.str().c_str(), tm.restart());
		return elliptics::error_info();
	}

};


}} // namespace ioremap::nullx
