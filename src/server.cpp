#include "nullx/asio.hpp"
#include "nullx/index.hpp"
#include "nullx/log.hpp"

#include <ebucket/bucket_processor.hpp>
#include <ribosome/expiration.hpp>
#include <ribosome/vector_lock.hpp>

#include <thevoid/rapidjson/stringbuffer.h>
#include <thevoid/rapidjson/prettywriter.h>
#include <thevoid/rapidjson/document.h>

#include <thevoid/server.hpp>
#include <thevoid/stream.hpp>

#include <unistd.h>
#include <signal.h>

#include <atomic>

using namespace ioremap;

class nullx_server : public thevoid::server<nullx_server>
{
public:
	virtual bool initialize(const rapidjson::Value &config) {
		srand(time(NULL));

		if (!elliptics_init(config))
			return false;

		on<nullx::on_upload_update_index<nullx_server>>(
			options::prefix_match("/upload"),
			options::methods("POST", "PUT")
		);

		on<nullx::on_login<nullx_server>>(
			options::prefix_match("/login"),
			options::methods("POST", "PUT")
		);

		on<nullx::on_signup<nullx_server>>(
			options::prefix_match("/signup"),
			options::methods("POST", "PUT")
		);

		return true;
	}

	std::shared_ptr<ebucket::bucket_processor> bucket_processor() const {
		return m_bp;
	}

	std::string meta_bucket() const {
		return m_meta_bucket;
	}

	std::string domain() const {
		return m_domain;
	}

	elliptics::error_info store_auth(const nullx::mailbox_t &mbox) {
		std::unique_lock<std::mutex> guard(m_auth_lock);
		m_mboxes.insert({mbox.cookie, mbox});
		guard.unlock();

		m_expire.insert(mbox.expires_at, [=] () {
					std::lock_guard<std::mutex> guard(m_auth_lock);
					m_mboxes.erase(mbox.cookie);
				});
		return elliptics::error_info();
	}

	bool check_cookie(const thevoid::http_request &req, nullx::mailbox_t &mbox) {
		auto cookie = req.headers().get("Cookie");
		if (!cookie)
			return false;

		std::vector<std::string> attrs;
		boost::split(attrs, *cookie, boost::is_any_of("; "));
		for (const auto &attr: attrs) {
			if (attr.size() <= 1)
				continue;

			std::vector<std::string> a;
			boost::split(a, attr, boost::is_any_of("="));

			if (a.size() != 2)
				continue;

			if (a[0] != nullx::cookie_prefix)
				continue;

			std::lock_guard<std::mutex> guard(m_auth_lock);
			auto it = m_mboxes.find(a[1]);
			if (it == m_mboxes.end())
				continue;

			if (std::chrono::system_clock::now() < it->second.expires_at) {
				mbox = it->second;
				return true;
			}

			return false;
		}

		return false;
	}

	void lock(const std::string &key) {
		m_vlock.lock(key);
	}
	void unlock(const std::string &key) {
		m_vlock.unlock(key);
	}
	bool try_lock(const std::string &key) {
		return m_vlock.try_lock(key);
	}

private:
	std::shared_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;
	std::shared_ptr<ebucket::bucket_processor> m_bp;

	long m_read_timeout = 60;
	long m_write_timeout = 60;

	std::string m_meta_bucket;
	std::string m_domain;

	std::mutex m_auth_lock;
	std::unordered_map<std::string, nullx::mailbox_t> m_mboxes;

	ribosome::expiration m_expire;
	ribosome::vector_lock m_vlock;

	bool elliptics_init(const rapidjson::Value &config) {
		dnet_config node_config;
		memset(&node_config, 0, sizeof(node_config));

		if (!prepare_config(config, node_config)) {
			return false;
		}

		if (!prepare_server(config)) {
			return false;
		}

		m_node.reset(new elliptics::node(std::move(swarm::logger(this->logger(), blackhole::log::attributes_t())), node_config));

		if (!prepare_node(config, *m_node)) {
			return false;
		}

		m_bp.reset(new ebucket::bucket_processor(m_node));

		if (!prepare_session(config)) {
			return false;
		}

		if (!prepare_buckets(config)) {
			return false;
		}

		return true;
	}

	bool prepare_config(const rapidjson::Value &config, dnet_config &node_config) {
		if (config.HasMember("io-thread-num")) {
			node_config.io_thread_num = config["io-thread-num"].GetInt();
		}
		if (config.HasMember("nonblocking-io-thread-num")) {
			node_config.nonblocking_io_thread_num = config["nonblocking-io-thread-num"].GetInt();
		}
		if (config.HasMember("net-thread-num")) {
			node_config.net_thread_num = config["net-thread-num"].GetInt();
		}

		return true;
	}

	bool prepare_node(const rapidjson::Value &config, elliptics::node &node) {
		if (!config.HasMember("remotes")) {
			NLOG_ERROR("\"application.remotes\" field is missed");
			return false;
		}

		std::vector<elliptics::address> remotes;

		auto &remotesArray = config["remotes"];
		for (auto it = remotesArray.Begin(), end = remotesArray.End(); it != end; ++it) {
				if (it->IsString()) {
					remotes.push_back(it->GetString());
				}
		}

		try {
			node.add_remote(remotes);
			m_session.reset(new elliptics::session(node));

			if (!m_session->get_routes().size()) {
				NLOG_ERROR("Didn't add any remote node, exiting.");
				return false;
			}
		} catch (const std::exception &e) {
			NLOG_ERROR("Could not add any out of %ld nodes.", remotes.size());
			return false;
		}

		return true;
	}

	bool prepare_session(const rapidjson::Value &config) {
		if (config.HasMember("read-timeout")) {
			auto &tm = config["read-timeout"];
			if (tm.IsInt())
				m_read_timeout = tm.GetInt();
		}

		if (config.HasMember("write-timeout")) {
			auto &tm = config["write-timeout"];
			if (tm.IsInt())
				m_write_timeout = tm.GetInt();
		}

		return true;
	}

	bool prepare_buckets(const rapidjson::Value &config) {
		if (!config.HasMember("buckets")) {
			NLOG_ERROR("\"application.buckets\" field is missed");
			return false;
		}

		auto &buckets = config["buckets"];

		std::set<std::string> bnames;
		for (auto it = buckets.Begin(), end = buckets.End(); it != end; ++it) {
			if (it->IsString()) {
				bnames.insert(it->GetString());
			}
		}

		if (!config.HasMember("metadata_groups")) {
			NLOG_ERROR("\"application.metadata_groups\" field is missed");
			return false;
		}

		std::vector<int> mgroups;
		auto &groups_meta_array = config["metadata_groups"];
		for (auto it = groups_meta_array.Begin(), end = groups_meta_array.End(); it != end; ++it) {
			if (it->IsInt())
				mgroups.push_back(it->GetInt());
		}

		if (!m_bp->init(mgroups, std::vector<std::string>(bnames.begin(), bnames.end())))
			return false;

		const char *meta_bucket = ebucket::get_string(config, "meta_bucket");
		if (!meta_bucket) {
			NLOG_ERROR("\"application.meta_bucket\" field is missed");
			return false;
		}
		m_meta_bucket.assign(meta_bucket);

		const char *domain = ebucket::get_string(config, "domain");
		if (!domain) {
			NLOG_ERROR("\"application.domain\" field is missed");
			return false;
		}
		m_domain.assign(domain);

		return true;
	}

	bool prepare_server(const rapidjson::Value &config) {
		(void) config;
		return true;
	}
};

int main(int argc, char **argv)
{
	if (argc == 1) {
		std::cerr << "Usage: " << argv[0] << " --config <config file>" << std::endl;
		return -1;
	}

	thevoid::register_signal_handler(SIGINT, thevoid::handle_stop_signal);
	thevoid::register_signal_handler(SIGTERM, thevoid::handle_stop_signal);
	thevoid::register_signal_handler(SIGHUP, thevoid::handle_reload_signal);
	thevoid::register_signal_handler(SIGUSR1, thevoid::handle_ignore_signal);
	thevoid::register_signal_handler(SIGUSR2, thevoid::handle_ignore_signal);

	thevoid::run_signal_thread();

	auto server = thevoid::create_server<nullx_server>();
	int err = server->run(argc, argv);

	thevoid::stop_signal_thread();

	return err;
}
