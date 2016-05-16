#pragma once

#include "nullx/crypto.hpp"
#include "nullx/jsonvalue.hpp"
#include "nullx/log.hpp"
#include "nullx/metadata.hpp"

#include <ebucket/bucket_processor.hpp>

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

	elliptics::error_info new_user(const std::string &username, const std::string &secret, mailbox_t &mbox) {
		ebucket::bucket b;
		auto err = m_bp.get_bucket(1024 * 1024, b);
		if (err)
			return err;

		mbox.username = username;
		mbox.secret = secret;
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

		auto async = s.write_data(username, data, 0);
		if (!async.is_valid()) {
			return elliptics::create_error(-EINVAL, "auth: could not create new user: %s, invalid async, data size: %ld",
					username.c_str(), data.size());
		}

		async.wait();
		if (async.error()) {
			return elliptics::create_error(async.error().code(),
					"auth: could not write new user data, bucket: %s, username: %s, data size: %ld, error: %s",
					m_meta_bucket.c_str(), username.c_str(), data.size(), async.error().message().c_str());
		}

		generate_temporal_bits(mbox);

		return elliptics::error_info();
	}

	elliptics::error_info login(const std::string &username, const std::string &secret, mailbox_t &mbox) {
		greylock::eurl url;
		url.bucket = m_meta_bucket;
		url.key = username;

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

		if (mbox.secret != secret) {
			return elliptics::create_error(-EPERM, "auth: secret mismatch for username: %s", url.str().c_str());
		}

		generate_temporal_bits(mbox);

		return elliptics::error_info();
	}

	elliptics::error_info parse_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer, mailbox_t &mbox) {
		(void) req;
		// this is needed to put ending zero-byte, otherwise rapidjson parser will explode
		std::string data(const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)), boost::asio::buffer_size(buffer));

#if 0
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
		const char *secret = ebucket::get_string(doc, "secret");

		if (!username || !secret) {
			return elliptics::create_error(-EINVAL, "username and secret must be specified");
		}
#endif

		swarm::url_query q(data);
		auto username = q.item_value("username");
		auto password = q.item_value("password");
		if (!username || !password) {
			return elliptics::create_error(-EINVAL, "username and password must be specified");
		}

		mbox.username.assign(*username);
		mbox.secret.assign(*password);
		return elliptics::error_info();
	}

	std::string serialize_reply(const mailbox_t &mbox, int error, const std::string &message) const {
		JsonValue reply;

		rapidjson::Value username_val(mbox.username.c_str(), mbox.username.size(), reply.GetAllocator());
		reply.AddMember("username", username_val, reply.GetAllocator());

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
		size_t sz = snprintf(buf, sizeof(buf), "%s=%s; Max-Age=%ld; Path=/; Domain=.%s",
				cookie_prefix.c_str(), mbox.cookie.c_str(), mbox.max_age, m_domain.c_str());

		return std::string(buf, sz);
	}

	void generate_temporal_bits(mailbox_t mbox) const {
		std::string data = mbox.username + mbox.secret + crypto::get_random_string() + std::to_string(rand() + time(NULL));
		mbox.cookie = crypto::calc_hash<CryptoPP::Weak::MD5>(data.data(), data.size());
		mbox.max_age = 60;
		mbox.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(mbox.max_age);
	}

private:
	ebucket::bucket_processor &m_bp;
	std::string m_meta_bucket;
	std::string m_domain;
};

template <typename Server, typename Stream, bool login>
class on_auth_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream> {
public:
	void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) req;

		auth a(*this->server()->bucket_processor(), this->server()->meta_bucket(), this->server()->domain());
		mailbox_t mbox;

		auto err = a.parse_request(req, buffer, mbox);
		if (err) {
			NLOG_ERROR("login: failed to parse request: %s [%d]", err.message().c_str(), err.code());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (login) {
			err = a.login(mbox.username, mbox.secret, mbox);
		} else {
			err = a.new_user(mbox.username, mbox.secret, mbox);
		}

		if (!err) {
			err = this->server()->store_auth(mbox);
		}

		if (err) {
			NLOG_ERROR("login: failed to create new user '%s': %s [%d]",
					mbox.username.c_str(), err.message().c_str(), err.code());

			int code = err.code();
			std::string message = err.message();
			int status = swarm::http_response::service_unavailable;
			if (err.code() == -EPERM) {
				status = swarm::http_response::unauthorized;
				message = "user " + mbox.username + ": invalid secret";
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
			reply.set_code(status);
			this->send_reply(std::move(reply), std::move(data));
			return;
		}

		std::string data = a.serialize_reply(mbox, 0, "");

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set("Access-Control-Allow-Origin", "*");
		reply.headers().set("Set-Cookie", a.cookie(mbox));
		this->send_reply(std::move(reply), std::move(data));
		return;
	}

private:
};

template <typename Server>
class on_login : public on_auth_base<Server, on_login<Server>, true>
{
public:
};

template <typename Server>
class on_signup : public on_auth_base<Server, on_signup<Server>, false>
{
public:
};


}} // namespace ioremap::nullx
