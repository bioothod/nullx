#pragma once

#include <thevoid/http_request.hpp>

#include <string>

namespace ioremap { namespace nullx { namespace url {

static inline const std::string key(const thevoid::http_request &req, bool have_bucket) {
	const auto &path = req.url().path_components();

	if (path.size() < 1) {
		return "";
	}
	if (have_bucket && path.size() < 2) {
		return "";
	}

	size_t prefix_size;
	if (!have_bucket) {
		prefix_size = 1 + path[0].size() + 1;
	} else {
		prefix_size = 1 + path[0].size() + 1 + path[1].size() + 1;
	}

	if (prefix_size >= req.url().path().size())
		return "";

	return req.url().path().substr(prefix_size);
}

static inline const std::string bucket(const thevoid::http_request &req) {
	const auto &path = req.url().path_components();
	if (path.size() <= 1)
		return "";

	return path[1];
}

}}} // namespace ioremap::nullx::url
