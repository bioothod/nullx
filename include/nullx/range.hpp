#pragma once

#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
#include <boost/lexical_cast.hpp>

#include <string>

namespace ioremap { namespace nullx {

struct srange_info
{
	boost::optional<size_t> offset;
	boost::optional<size_t> size;

	static bool parse_range(const std::string &range, srange_info &info) {
		info.offset.reset();
		info.size.reset();

		if (range.size() <= 1)
			return false;

		try {
			const auto separator = range.find('-');
			if (separator == std::string::npos)
				return false;

			if (separator > 0)
				info.offset = boost::lexical_cast<size_t>(range.substr(0, separator));

			if (separator + 1 < range.size()) {
				size_t end = boost::lexical_cast<size_t>(range.substr(separator + 1));
				info.size = end + 1; // 0-499 means first 500 bytes

				if (info.offset) {
					if (*info.offset >= *info.size)
						return false;

					info.size = *info.size - *info.offset;
				}
			}
		} catch (...) {
			return false;
		}

		if (!info.offset && !info.size)
			return false;

		return true;
	}

	static std::vector<srange_info> parse(std::string range, bool *ok) {
		*ok = false;

		if (range.compare(0, 6, "bytes=") != 0)
			return std::vector<srange_info>();

		*ok = true;

		std::vector<srange_info> ranges;

		std::vector<std::string> ranges_str;
		range.erase(range.begin(), range.begin() + 6);
		boost::split(ranges_str, range, boost::is_any_of(","));

		for (auto it = ranges_str.begin(); it != ranges_str.end(); ++it) {
			srange_info info;
			if (parse_range(*it, info))
				ranges.push_back(info);
		}

		return ranges;
	}
};

}} // namespace ioremap::nullx

