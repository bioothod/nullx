#pragma once

#include <msgpack.hpp>

namespace ioremap { namespace nullx {

struct mailbox_t {
	std::string		username;
	std::string		secret;
	std::string		meta_bucket;
	std::string		meta_index;

	MSGPACK_DEFINE(username, secret, meta_bucket, meta_index);

	std::string		cookie;
	std::chrono::system_clock::time_point	expires_at;
	long			max_age;
};

}} // namespace ioremap::nullx
