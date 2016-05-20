#pragma once

#include <thevoid/http_request.hpp>

#include <string>

namespace ioremap { namespace nullx { namespace url {

static inline const std::string key(const thevoid::http_request &req, bool have_bucket) {
	std::string key;

	const auto &path = req.url().path_components();

	if (!have_bucket) {
		size_t prefix_size = 1 + path[0].size() + 1;
		key = req.url().path().substr(prefix_size);
	} else {
		size_t prefix_size = 1 + path[0].size() + 1 + path[1].size() + 1;
		key = req.url().path().substr(prefix_size);
	}

	return key;
}

static inline const std::string bucket(const thevoid::http_request &req) {
	const auto &path = req.url().path_components();

	return path[1];
}

}}} // namespace ioremap::nullx::url
