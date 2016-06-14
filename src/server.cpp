#include "nullx/asio.hpp"
#include "nullx/log.hpp"
#include "nullx/transcode.hpp"
#include "nullx/upload.hpp"

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

		on<nullx::on_transcode<nullx_server>>(
			options::prefix_match("/transcode/"),
			options::methods("POST", "PUT")
		);

		return true;
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

	elliptics::session session() {
		return *m_session;
	}

private:
	std::shared_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;

	long m_read_timeout = 60;
	long m_write_timeout = 60;

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

		if (!prepare_session(config)) {
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

	bool prepare_server(const rapidjson::Value &config) {
		if (!config.HasMember("tmp_dir")) {
			NLOG_ERROR("\"application.tmp_dir\" field is missed");
			return false;
		}
		auto &td = config["tmp_dir"];
		if (!td.IsString()) {
			NLOG_ERROR("\"application.tmp_dir\" must be string");
			return false;
		}
		m_tmp_dir.assign(td.GetString());

		int num_workers = 16;
		if (config.HasMember("transcoding_workers")) {
			auto &tw = config["transcoding_workers"];
			if (tw.IsInt()) {
				num_workers = tw.GetInt();
			}
		}
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
