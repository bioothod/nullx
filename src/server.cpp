#include "nullx/asio.hpp"
#include "nullx/get.hpp"
#include "nullx/index.hpp"
#include "nullx/log.hpp"
#include "nullx/mime.hpp"
#include "nullx/transcode.hpp"
#include "nullx/upload.hpp"

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

		on<nullx::on_user_login<nullx_server>>(
			options::prefix_match("/user_login"),
			options::methods("POST", "PUT")
		);
		on<nullx::on_user_signup<nullx_server>>(
			options::prefix_match("/user_signup"),
			options::methods("POST", "PUT")
		);
		on<nullx::on_user_update<nullx_server>>(
			options::prefix_match("/user_update"),
			options::methods("POST", "PUT")
		);


		on<nullx::on_upload_auth_media<nullx_server>>(
			options::prefix_match("/upload/"),
			options::methods("POST", "PUT")
		);
		on<nullx::on_get_auth<nullx_server>>(
			options::prefix_match("/get/"),
			options::methods("GET")
		);


		on<nullx::on_index<nullx_server>>(
			options::prefix_match("/index"),
			options::methods("POST", "PUT")
		);
		on<nullx::on_list<nullx_server>>(
			options::prefix_match("/list"),
			options::methods("POST", "PUT")
		);


		on<nullx::on_static<nullx_server>>(
			options::prefix_match("/"),
			options::methods("GET")
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
		boost::split(attrs, *cookie, boost::is_any_of(";"));
		for (auto &attr: attrs) {
			boost::trim(attr);
			if (attr.size() <= 1)
				continue;

			auto eqpos = attr.find('=');
			if (eqpos == std::string::npos)
				continue;

			if (attr.substr(0, eqpos) != nullx::cookie_prefix)
				continue;

			std::string cookie = attr.substr(eqpos+1);

			std::lock_guard<std::mutex> guard(m_auth_lock);
			auto it = m_mboxes.find(cookie);
			if (it == m_mboxes.end())
				continue;

			if (std::chrono::system_clock::now() < it->second.expires_at) {
				mbox = it->second;
				return true;
			}

			continue;
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

	const std::string &static_root_dir() const {
		return m_static_root_dir;
	}

	std::string content_type(const std::string &name) const {
		return m_mime->find(name);
	}

	const std::string &tmp_dir() const {
		return m_tmp_dir;
	}

	typedef std::function<void (const std::string &output_file, const elliptics::error_info &error)> transcoding_completion_t;
	void schedule_transcoding(const std::string &input_file, transcoding_completion_t completion) {
		ribosome::fpool::message msg(input_file.size());
		memcpy(msg.data.get(), input_file.data(), input_file.size());
		m_transcode_ctl->schedule(msg, std::bind(&nullx_server::transcode_completion, this,
					input_file, completion, std::placeholders::_1));
	}

private:
	std::shared_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;
	std::shared_ptr<ebucket::bucket_processor> m_bp;

	long m_read_timeout = 60;
	long m_write_timeout = 60;

	std::string m_meta_bucket;
	std::string m_domain;

	std::string m_static_root_dir;

	std::mutex m_auth_lock;
	std::unordered_map<std::string, nullx::mailbox_t> m_mboxes;

	ribosome::expiration m_expire;
	ribosome::vector_lock m_vlock;

	std::unique_ptr<nullx::mime> m_mime;

	std::string m_tmp_dir;

	std::unique_ptr<nullx::transcode_controller> m_transcode_ctl;

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

		return true;
	}

	bool prepare_server(const rapidjson::Value &config) {
		const char *domain = ebucket::get_string(config, "domain");
		if (!domain) {
			NLOG_ERROR("\"application.domain\" field is missed");
			return false;
		}
		m_domain.assign(domain);

		const char *root = ebucket::get_string(config, "static_root_dir");
		if (!root) {
			NLOG_ERROR("\"application.static_root_dir\" field is missed");
			return false;
		}
		m_static_root_dir.assign(root);

		const char *mime_file = ebucket::get_string(config, "mime_file");
		if (!mime_file) {
			NLOG_ERROR("\"application.mime_file\" field is missed");
			return false;
		}
		m_mime.reset(new nullx::mime("application/octet-stream", mime_file));

		const char *tmp_dir = ebucket::get_string(config, "tmp_dir");
		if (!tmp_dir) {
			NLOG_ERROR("\"application.tmp_dir\" field is missed");
			return false;
		}
		m_tmp_dir.assign(tmp_dir);

		int num_workers = ebucket::get_int64(config, "transcoding_workers", 16);
		m_transcode_ctl.reset(new nullx::transcode_controller(num_workers));
		return true;
	}

	void transcode_completion(const std::string &input_file, transcoding_completion_t completion,
			const ribosome::fpool::message &reply) {
		if (reply.header.status) {
			std::string output_file;
			elliptics::error_info err = elliptics::create_error(reply.header.status,
					"failed to transcode file %s", input_file.c_str());
			NLOG_ERROR("transcoding failed: file: %s, reply: %s",
				input_file.c_str(), reply.str().c_str());

			completion(output_file, err);
			return;
		}

		std::string output_file(reply.data.get(), reply.header.size);
		NLOG_INFO("transcoding completed: file: %s -> %s, reply: %s",
				input_file.c_str(), output_file.c_str(), reply.str().c_str());
		completion(output_file, elliptics::error_info());
	}

};

int main(int argc, char **argv)
{
	if (argc == 1) {
		std::cerr << "Usage: " << argv[0] << " --config <config file>" << std::endl;
		return -1;
	}

	av_register_all();
	avfilter_register_all();

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
