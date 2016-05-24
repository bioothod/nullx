#pragma once

#include <msgpack.hpp>

namespace ioremap { namespace nullx {

struct mailbox_t {
	std::string		username;
	std::string		password;
	std::string		realname;
	std::string		email;
	std::string		meta_bucket;
	std::string		meta_index;

	MSGPACK_DEFINE(username, password, realname, email, meta_bucket, meta_index);

	std::string		cookie;
	std::chrono::system_clock::time_point	expires_at;
	long			max_age;

	std::string index(const std::string &name) {
		return username + "." + name;
	}

	std::string filename(const std::string &name) {
		return username + "/" + name;
	}
};

}} // namespace ioremap::nullx
