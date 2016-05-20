#pragma once

#include <fstream>
#include <string>
#include <unordered_map>

namespace ioremap { namespace nullx {

class mime {
public:
	mime(const std::string &def, const std::string &path) : m_default(def) {
		std::ifstream in(path.c_str());
		std::string line;

		while (std::getline(in, line)) {
			auto pos = line.find('#');
			if (pos != std::string::npos) {
				line.resize(pos);
			}

			if (line.size() < 3)
				continue;

			std::vector<std::string> s;
			boost::split(s, line, boost::is_any_of(" \t"));

			for (size_t i = 1; i < s.size(); ++i) {
				m_map[s[i]] = s[0];
			}
		}
	}

	std::string find(const std::string &name) const {
		auto dot = name.rfind('.');
		if (dot == std::string::npos)
			return m_default;

		auto it = m_map.find(name.substr(dot + 1));
		if (it == m_map.end())
			return m_default;

		return it->second;
	}

private:
	std::unordered_map<std::string, std::string> m_map;
	std::string m_default;
};

}} // namespace ioremap::nullx
