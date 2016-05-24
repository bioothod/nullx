#pragma once

#include "nullx/crypto.hpp"
#include "nullx/jsonvalue.hpp"
#include "nullx/log.hpp"
#include "nullx/metadata.hpp"

#include <ebucket/bucket_processor.hpp>
#include <greylock/index.hpp>
#include <ribosome/vector_lock.hpp>

#include <greylock/io.hpp>
#include <swarm/url_query.hpp>

namespace ioremap { namespace nullx {

namespace {
	static const std::string cookie_prefix = "nx";
};

class auth {
public:
	auth(ebucket::bucket_processor &bp, const std::string &meta_bucket, const std::string &domain)
		: m_bp(bp)
		, m_meta_bucket(meta_bucket)
		, m_domain(domain)
	{
	}

	elliptics::error_info new_user(mailbox_t &mbox) {
		ebucket::bucket b;
		auto err = m_bp.get_bucket(1024 * 1024, b);
		if (err)
			return err;

		mbox.meta_bucket = b->name();
		mbox.meta_index = "tags";

		std::stringstream buffer;
		msgpack::pack(buffer, mbox);
		buffer.seekg(0);

		err = m_bp.find_bucket(m_meta_bucket, b);
		if (err)
			return err;

		std::string data = buffer.str();
		elliptics::session s = b->session();
		s.set_ioflags(DNET_IO_FLAGS_COMPARE_AND_SWAP);

		auto async = s.write_data(generate_username_key(mbox.username), data, 0);
		if (!async.is_valid()) {
			return elliptics::create_error(-EINVAL, "auth: could not write new user: %s, "
					"invalid async, data size: %ld",
					mbox.username.c_str(), data.size());
		}

		async.wait();
		if (async.error()) {
			return elliptics::create_error(async.error().code(),
					"auth: could not write new user data, bucket: %s, username: %s, data size: %ld, error: %s",
					m_meta_bucket.c_str(), mbox.username.c_str(), data.size(), async.error().message().c_str());
		}

		return elliptics::error_info();
	}

	elliptics::error_info update_user(mailbox_t &mbox) {
		std::stringstream buffer;
		msgpack::pack(buffer, mbox);
		buffer.seekg(0);

		ebucket::bucket b;
		auto err = m_bp.find_bucket(m_meta_bucket, b);
		if (err)
			return err;

		std::string data = buffer.str();
		elliptics::session s = b->session();

		auto async = s.write_data(generate_username_key(mbox.username), data, 0);
		if (!async.is_valid()) {
			return elliptics::create_error(-EINVAL, "auth: could not update user: %s, "
					"invalid async, data size: %ld",
					mbox.username.c_str(), data.size());
		}

		async.wait();
		if (async.error()) {
			return elliptics::create_error(async.error().code(),
					"auth: could not update username: %s, data size: %ld, error: %s",
					mbox.username.c_str(), data.size(), async.error().message().c_str());
		}

		return elliptics::error_info();
	}

	elliptics::error_info login(mailbox_t &mbox) {
		greylock::eurl url;
		url.bucket = m_meta_bucket;
		url.key = generate_username_key(mbox.username);

		elliptics::async_read_result async = greylock::io::read_data(m_bp, url, false);
		if (!async.is_valid()) {
			return elliptics::create_error(-EINVAL, "auth: invalid async read result for username %s", url.str().c_str());
		}

		if (async.error()) {
			return elliptics::create_error(async.error().code(), "auth: could not read data for username %s: %s",
					url.str().c_str(), async.error().message().c_str());
		}

		elliptics::read_result_entry ent = async.get_one();
		if (ent.error() || !ent.is_valid()) {
			int code = ent.error().code();
			if (!ent.is_valid())
				code = -EINVAL;

			return elliptics::create_error(code,
					"auth: could not get read entry for username %s: entry valid: %d, error: %s",
					url.str().c_str(), ent.is_valid(), async.error().message().c_str());
		}

		std::string user_password = mbox.password;

		const auto &file = ent.file();
		try {
			msgpack::unpacked result;
			msgpack::unpack(&result, file.data<char>(), file.size());
			result.get().convert(&mbox);
		} catch (const std::exception &e) {
			BH_LOG(m_bp.logger(), INDEXES_LOG_ERROR, "auth: failed to unpack user metadata: username: %s, data size: %ld: %s",
				url.str().c_str(), file.size(), e.what());
			return elliptics::create_error(-EINVAL, "auth: failed to unpack user metadata: username: %s, data size: %ld: %s",
				url.str().c_str(), file.size(), e.what());
		}

		if (mbox.password != user_password) {
			return elliptics::create_error(-EPERM, "auth: password mismatch for username: %s", url.str().c_str());
		}

		return elliptics::error_info();
	}

	elliptics::error_info parse_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer, mailbox_t &mbox) {
		(void) req;
		// this is needed to put ending zero-byte, otherwise rapidjson parser will explode
		std::string data(const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)), boost::asio::buffer_size(buffer));

		rapidjson::Document doc;
		doc.Parse<0>(data.c_str());

		if (doc.HasParseError()) {
			return elliptics::create_error(-EINVAL, "could not parse document: %s, error offset: %zd, data: %s", 
					doc.GetParseError(), doc.GetErrorOffset(), data.c_str());
		}

		if (!doc.IsObject()) {
			return elliptics::create_error(-EINVAL, "document must be object, its type: %d", doc.GetType());
		}

		const char *username = ebucket::get_string(doc, "username");
		const char *password = ebucket::get_string(doc, "password");
		const char *email = ebucket::get_string(doc, "email");
		const char *realname = ebucket::get_string(doc, "realname", username);

		if (!username || !password) {
			return elliptics::create_error(-EINVAL, "username and password must be specified");
		}

		mbox.username.assign(username);
		mbox.password.assign(password);
		mbox.realname.assign(realname);

		if (email)
			mbox.email.assign(email);
#if 0
		swarm::url_query q(data);
		auto username = q.item_value("username");
		auto password = q.item_value("password");
		if (!username || !password) {
			return elliptics::create_error(-EINVAL, "username and password must be specified");
		}

		mbox.username.assign(*username);
		mbox.password.assign(*password);
#endif
		return elliptics::error_info();
	}

	std::string serialize_reply(const mailbox_t &mbox, int error, const std::string &message) const {
		JsonValue reply;

		rapidjson::Value username_val(mbox.username.c_str(), mbox.username.size(), reply.GetAllocator());
		reply.AddMember("username", username_val, reply.GetAllocator());

		rapidjson::Value realname_val(mbox.realname.c_str(), mbox.realname.size(), reply.GetAllocator());
		reply.AddMember("realname", realname_val, reply.GetAllocator());

		rapidjson::Value email_val(mbox.email.c_str(), mbox.email.size(), reply.GetAllocator());
		reply.AddMember("email", email_val, reply.GetAllocator());

		rapidjson::Value meta_bucket_val(mbox.meta_bucket.c_str(), mbox.meta_bucket.size(), reply.GetAllocator());
		reply.AddMember("meta_bucket", meta_bucket_val, reply.GetAllocator());

		rapidjson::Value meta_index_val(mbox.meta_index.c_str(), mbox.meta_index.size(), reply.GetAllocator());
		reply.AddMember("meta_index", meta_index_val, reply.GetAllocator());

		rapidjson::Value err;
		err.SetObject();
		err.AddMember("code", error, reply.GetAllocator());

		rapidjson::Value error_message_val(message.c_str(), message.size(), reply.GetAllocator());
		err.AddMember("message", error_message_val, reply.GetAllocator());

		reply.AddMember("error", err, reply.GetAllocator());

		return reply.ToString();
	}

	std::string cookie(const mailbox_t &mbox) const {
		char buf[4096];
		std::string domain;

		if (!m_domain.empty()) {
			domain = "; Path=/; Domain=." + m_domain;
		}

		char ts[256];
		struct tm tm;
		time_t tt = std::chrono::system_clock::to_time_t(mbox.expires_at);
		gmtime_r(&tt, &tm); // cookie expiration string must be in GMT timezone
		strftime(ts, sizeof(ts), "%a, %d %b %Y %T GMT", &tm);

		size_t sz = snprintf(buf, sizeof(buf), "%s=%s; Expires=%s%s",
				cookie_prefix.c_str(), mbox.cookie.c_str(), ts, domain.c_str());

		return std::string(buf, sz);
	}

	void generate_temporal_bits(mailbox_t &mbox) const {
		std::string data = mbox.username + mbox.password + crypto::get_random_string() + std::to_string(rand() + time(NULL));
		mbox.cookie = crypto::calc_hash<CryptoPP::Weak::MD5>(data.data(), data.size());
		mbox.max_age = 600;
		mbox.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(mbox.max_age);
	}

private:
	ebucket::bucket_processor &m_bp;
	std::string m_meta_bucket;
	std::string m_domain;

	std::string generate_username_key(const std::string &key) {
		std::string prefix = "u";

		char tmp[prefix.size() + 1 + key.size() + 1];
		int sz = snprintf(tmp, sizeof(tmp), "%s.%s", prefix.c_str(), key.c_str());
		tmp[prefix.size()] = '\0';

		return std::string(tmp, sz);
	}
};

template <typename Server, typename Stream, bool login>
class on_auth_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream> {
public:
	virtual elliptics::error_info process(auth &a, mailbox_t &mbox) = 0;

	void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		auth a(*this->server()->bucket_processor(), this->server()->meta_bucket(), this->server()->domain());
		mailbox_t mbox;

		auto err = a.parse_request(req, buffer, mbox);
		if (err) {
			NLOG_ERROR("auth: url: %s, failed to parse request: %s [%d]",
					req.url().to_human_readable().c_str(),
					err.message().c_str(), err.code());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		err = process(a, mbox);
		if (!err) {
			a.generate_temporal_bits(mbox);
			err = this->server()->store_auth(mbox);
		}

		if (err) {
			NLOG_ERROR("auth: url: %s, failed to process user: %s, error: %s [%d]",
					req.url().to_human_readable().c_str(),
					mbox.username.c_str(), err.message().c_str(), err.code());

			int code = err.code();
			std::string message = err.message();
			int status = swarm::http_response::service_unavailable;
			if (err.code() == -EPERM) {
				status = swarm::http_response::unauthorized;
				message = "user " + mbox.username + ": invalid password";
			}
			if (err.code() == -EBADFD) {
				code = -EEXIST;
				status = swarm::http_response::bad_request;
				message = "user " + mbox.username + ": already exists";
			}

			std::string data = a.serialize_reply(mbox, code, message);

			thevoid::http_response reply;
			reply.headers().set("Access-Control-Allow-Origin", "*");
			reply.headers().set_content_type("text/json; charset=utf-8");
			reply.headers().set_content_length(data.size());
			reply.set_code(status);
			this->send_reply(std::move(reply), std::move(data));
			return;
		}

		std::string data = a.serialize_reply(mbox, 0, "");
		NLOG_NOTICE("auth: url: %s, request: %.*s, cookie: %s, reply: %s",
				req.url().to_human_readable().c_str(),
				(int)boost::asio::buffer_size(buffer), boost::asio::buffer_cast<const char*>(buffer),
				a.cookie(mbox).c_str(),
				data.c_str());

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set("Set-Cookie", a.cookie(mbox));
		reply.headers().set_content_length(data.size());
		this->send_reply(std::move(reply), std::move(data));
		return;
	}

private:
};

template <typename Server>
class on_user_login : public on_auth_base<Server, on_user_login<Server>, true>
{
public:
	elliptics::error_info process(auth &a, mailbox_t &mbox) {
		auto err = a.login(mbox);
		if (err)
			return err;

		NLOG_INFO("auth: login: welcome: username: %s, realname: %s, email: %s, meta_bucket: %s, meta_index: %s",
				mbox.username.c_str(), mbox.realname.c_str(), mbox.email.c_str(),
				mbox.meta_bucket.c_str(), mbox.meta_index.c_str());
		return err;
	}
};

template <typename Server>
class on_user_signup : public on_auth_base<Server, on_user_signup<Server>, false>
{
public:
	elliptics::error_info process(auth &a, mailbox_t &mbox) {
		auto err = a.new_user(mbox);
		if (err)
			return err;

		greylock::eurl idx;
		idx.bucket = mbox.meta_bucket;
		idx.key = mbox.meta_index;

		try {
			ribosome::locker<Server> l(this->server(), idx.str());
			std::unique_lock<ribosome::locker<Server>> lk(l);

			greylock::read_write_index index(*this->server()->bucket_processor(), idx);
		} catch (const elliptics::error &e) {
			return elliptics::create_error(e.error_code(),
					"auth: could not create meta index: %s, username: %s, error: %s",
					idx.str().c_str(), mbox.username.c_str(), e.what());
		} catch (const std::exception &e) {
			return elliptics::create_error(-EINVAL,
					"auth: could not create meta index: %s, username: %s, error: %s",
					idx.str().c_str(), mbox.username.c_str(), e.what());
		}

		return elliptics::error_info();
	}
};

template <typename Server>
class on_user_update : public on_auth_base<Server, on_user_update<Server>, false>
{
public:
	elliptics::error_info process(auth &a, mailbox_t &mbox) {
		return a.update_user(mbox);
	}
};


}} // namespace ioremap::nullx
