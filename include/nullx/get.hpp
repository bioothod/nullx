#pragma once

#include "nullx/asio.hpp"
#include "nullx/log.hpp"
#include "nullx/range.hpp"
#include "nullx/url.hpp"

#include <ebucket/bucket.hpp>
#include <boost/filesystem.hpp>

namespace ioremap { namespace nullx {

class iodevice
{
public:
	typedef std::function<void (const elliptics::data_pointer &data, const elliptics::error_info &error, bool last)> function;

	iodevice(size_t offset, size_t size) : m_offset(offset), m_size(size), m_orig_size(size) {}
	iodevice(const iodevice &) = delete;
	iodevice &operator=(const iodevice &other) = delete;
	virtual ~iodevice() {}

	size_t orig_size() const {
		return m_orig_size;
	}
	size_t size() const {
		return m_size;
	}
	size_t offset() const {
		return m_offset;
	}
	virtual void update(ssize_t offset, ssize_t size) {
		m_offset += offset;
		m_size += size;
	}

	virtual void read(size_t limit, const function &handler) = 0;
private:
	size_t m_offset;
	size_t m_size;
	size_t m_orig_size;
};

class buffer_device : public iodevice
{
public:
	buffer_device(const std::string &data)
		: iodevice(0, data.size()), m_data(elliptics::data_pointer::copy(data))
	{
	}
	buffer_device(elliptics::data_pointer &&data)
		: iodevice(0, data.size()), m_data(std::move(data))
	{
	}

	void read(size_t limit, const function &handler) {
		ssize_t sz = std::min(size(), limit);
		elliptics::data_pointer res = m_data.slice(offset(), sz);
		update(+sz, -sz);

		handler(res, elliptics::error_info(), size() == 0);
	}

private:
	elliptics::data_pointer m_data;
};

class fs_device : public iodevice
{
public:
	fs_device(int fd, size_t offset, size_t size)
		: iodevice(offset, size), m_fd(fd)
	{
	}

	void read(size_t limit, const function &handler) {
		ssize_t sz = std::min(size(), limit);

		elliptics::data_pointer dp = elliptics::data_pointer::allocate(sz);
		ssize_t err = pread(m_fd, dp.data(), sz, offset());
		if (err <= 0) {
			handler(dp.slice(0, 0),
				elliptics::create_error(-errno,
					"could not read file: offset: %ld, chunk-size: %ld, rest-size: %ld",
					offset(), sz, size()),
				false);
			return;
		}

		update(+err, -err);
		handler(dp.slice(0, sz), elliptics::error_info(), size() == 0);
	}

private:
	int m_fd;
};

class async_device : public iodevice
{
public:
	async_device(const elliptics::session &session, const elliptics::key &id, size_t offset, size_t size)
		: iodevice(offset, size), m_session(session), m_id(id)
	{
	}

	void read(size_t limit, const function &handler) {
		size_t size = std::min(this->size(), limit);

		m_session.read_data(m_id, offset(), size).connect(std::bind(&async_device::on_result, this,
			std::placeholders::_1, std::placeholders::_2, handler));
	}

private:
	void on_result(const elliptics::sync_read_result &result,
		const elliptics::error_info &error, const function &handler) {
		if (error) {
			handler(elliptics::data_pointer(), error, size() == 0);
			return;
		}

		const elliptics::read_result_entry &entry = result[0];
		const elliptics::data_pointer &file = entry.file();

		ssize_t fs = file.size();
		update(fs, -fs);

		handler(file, elliptics::error_info(), size() == 0);
	}

	elliptics::session m_session;
	elliptics::key m_id;
};

template <typename Server, typename Stream>
class on_read_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	void read_next_chunk() {
		auto &dev = m_devices[m_device_index];
		dev->read(m_buffer_size, std::bind(&on_read_base::on_chunk_read, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	}

	virtual void add_async(size_t offset, size_t size) = 0;

	elliptics::error_info fill_ranges() {
		for (auto &range: m_ranges) {
			// -500 case, i.e. read last 500 bytes
			// return error if total file size is less than requested number of bytes
			if (!range.offset) {
				if (*range.size > m_total_size) {
					return elliptics::create_error(-ESPIPE,
							"invalid range: offset: none, size: %ld, total_size: %ld",
							*range.size, m_total_size);
				}

				range.offset = m_total_size - *range.size;
				continue;
			}

			// 500- case, i.e. read everything from the 500'th byte to the end
			// return error if offset is past the total size
			if (!range.size) {
				if (*range.offset > m_total_size) {
					return elliptics::create_error(-ESPIPE,
							"invalid range: offset: %ld, size: none, total_size: %ld",
							*range.offset, m_total_size);
				}

				range.size = m_total_size - *range.offset;
			}
		}

		if (m_ranges.size() == 1) {
			on_range(m_ranges.front(), m_total_size, m_timestamp);
		} else {
			on_ranges(m_ranges, m_total_size, m_timestamp);
		}

		return elliptics::error_info();
	}

	std::string create_content_range(size_t begin, size_t end, size_t data_size) {
		std::string result = "bytes ";
		result += boost::lexical_cast<std::string>(begin);
		result += "-";
		result += boost::lexical_cast<std::string>(end);
		result += "/";
		result += boost::lexical_cast<std::string>(data_size);
		return result;
	}

	void on_range(const srange_info &range, size_t data_size, const dnet_time &ts) {
		auto content_range = create_content_range(*range.offset, *range.offset + *range.size - 1, data_size);

		thevoid::http_response reply;

		auto &info = m_ranges.front();
		if (*info.offset || *info.size != data_size) {
			reply.set_code(swarm::http_response::partial_content);
		} else {
			reply.set_code(swarm::http_response::ok);
		}
		reply.headers().set_content_type(this->server()->content_type(m_url));
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");
		reply.headers().add("Content-Range", content_range);

		NLOG_INFO("buffered-get: on_range: url: %s: Content-Range: %s, offset: %ld, size: %ld, total_size: %ld",
				m_url.c_str(), content_range.c_str(), *info.offset, *info.size, m_total_size);

		add_async(*range.offset, *range.size);

		start(std::move(reply));
	}

	void on_ranges(const std::vector<srange_info> &ranges, size_t data_size, const dnet_time &ts) {
		char boundary[17];
		for (size_t i = 0; i < 2; ++i) {
			uint32_t tmp = rand();
			sprintf(boundary + i * 8, "%08X", tmp);
		}

		std::string result;
		for (auto it = ranges.begin(); it != ranges.end(); ++it) {
			result += "--";
			result += boundary;
			result += "\r\n"
				"Content-Type: " + this->server()->content_type(m_url) + "\r\n"
				"Content-Range: ";
			result += create_content_range(*it->offset, *it->offset + *it->size - 1, data_size);
			result += "\r\n\r\n";
			add_buffer(std::move(result));
			result.clear();

			add_async(*it->offset, *it->size);
			result += "\r\n";
		}
		result += "--";
		result += boundary;
		result += "--\r\n";
		add_buffer(std::move(result));

		thevoid::http_response reply;
		reply.set_code(swarm::http_response::partial_content);
		reply.headers().set_content_type(std::string("multipart/byteranges; boundary=") + boundary);
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");

		start(std::move(reply));
	}

	// @last means the last chunk in given device, not the last chunk in client's request
	void on_chunk_read(const elliptics::data_pointer &file, const elliptics::error_info &error, bool last) {
		size_t chunk_offset = m_devices[m_device_index]->offset() - file.size();

		if (error) {
			NLOG_ERROR("buffered-get: on_chunk_read: url: %s: error: %s, "
					"offset: %lu, last: %d",
					m_url.c_str(), error.message().c_str(), chunk_offset, last);

			auto ec = boost::system::errc::make_error_code(static_cast<boost::system::errc::errc_t>(-error.code()));
			this->reply()->close(ec);
			return;
		}

		NLOG_NOTICE("buffered-get: on_chunk_read: url: %s: "
				"offset: %lu, data-size: %lu, last-in-current-device: %d, device: %zd/%zd",
				m_url.c_str(), chunk_offset, (unsigned long)file.size(), last,
				m_device_index, m_devices.size());


		if (last) {
			m_device_index++;
		}

		if (m_device_index == m_devices.size()) {
			this->send_data(elliptics::data_pointer(file),
					std::bind(&on_read_base::close, this->shared_from_this(), std::placeholders::_1));
			return;
		}

		const size_t second_size = file.size() / 2;

		auto first_part = file.slice(0, file.size() - second_size);
		auto second_part = file.slice(first_part.size(), second_size);

		NLOG_NOTICE("buffered-get-redirect: on_chunk_read: url: %s: "
				"ofset: %lu, data-size: %lu, last: %d, "
				"first-part: offset: %zd, size: %zd, second-part: offset: %zd, size: %zd",
				m_url.c_str(), chunk_offset, (unsigned long)file.size(), last,
				first_part.offset(), first_part.size(), second_part.offset(), second_part.size());

		this->send_data(std::move(first_part), std::bind(&on_read_base::on_part_sent,
			this->shared_from_this(), chunk_offset + file.size(), std::placeholders::_1, second_part));
	}

	void on_part_sent(size_t offset, const boost::system::error_code &error, const elliptics::data_pointer &second_part) {
		if (error) {
			NLOG_ERROR("buffered-get: on_part_sent: url: %s: error: %s, "
					"next-read-offset: %lu, second-part-size: %lu",
					m_url.c_str(), error.message().c_str(),
					offset, (unsigned long)second_part.size());
		} else {
			NLOG_NOTICE("buffered-get: on_part_sent: url: %s: "
					"next-read-offset: %lu, second-part-size: %lu",
					m_url.c_str(), offset, (unsigned long)second_part.size());
		}

		if (!second_part.empty())
			this->send_data(elliptics::data_pointer(second_part),
					std::function<void (const boost::system::error_code &)>());
		read_next_chunk();
	}

protected:
	void start(thevoid::http_response &&response) {
		size_t size = 0;

		for (auto it = m_devices.begin(); it != m_devices.end(); ++it)
			size += (*it)->orig_size();

		response.headers().set_content_length(size);

		this->send_headers(std::move(response), std::function<void (const boost::system::error_code &)>());
		read_next_chunk();
	}

	void add_buffer(std::string &&data) {
		m_devices.emplace_back(new buffer_device(std::move(data)));
	}
	void add_buffer(elliptics::data_pointer &&data) {
		m_devices.emplace_back(new buffer_device(std::move(data)));
	}

	std::deque<std::unique_ptr<iodevice>> m_devices;
	// index of the device to be processed from @m_devices array
	// when it reaches m_devices.size(), there will be no more packets to client
	size_t m_device_index = 0;

	std::vector<srange_info> m_ranges;

	size_t m_total_size = 0;
	struct dnet_time m_timestamp;

	std::string m_url;
	uint64_t m_buffer_size = 5 * 1024 * 1024;
};

template <typename Server>
class on_get : public on_read_base<Server, on_get<Server>>
{
public:
	virtual void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		const auto &query = req.url().query();
		this->m_url = req.url().to_human_readable();

		(void) buffer;

		m_key = url::key(req, true);
		std::string bucket = url::bucket(req);

		ebucket::bucket b;
		elliptics::error_info err = this->server()->bucket_processor()->find_bucket(bucket, b);
		if (err) {
			NLOG_ERROR("buffered-get: on_request: url: %s: could not find bucket '%s': %s [%d]",
					this->m_url.c_str(), bucket.c_str(),
					err.message().c_str(), err.code());
			this->send_reply(swarm::http_response::not_found);
			return;
		}

		m_session.reset(new elliptics::session(b->session()));
		m_session->set_filter(elliptics::filters::positive);

		NLOG_INFO("buffered-get: on_request: url: %s, bucket: %s, key: %s",
				this->m_url.c_str(),
				bucket.c_str(), m_key.to_string().c_str());

		if (query.has_item("offset") || query.has_item("size")) {
			srange_info info;
			try {
				info.offset = query.item_value("offset", 0lu);
				info.size = query.item_value("size", 0lu);
			} catch (const std::exception &e) {
				NLOG_ERROR("buffered-get: on_request: url: %s: invalid size/offset parameters: %s",
						this->m_url.c_str(), e.what());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}

			this->m_ranges.push_back(info);
		} else {
			auto range = this->request().headers().get("Range");
			if (range) {
				NLOG_INFO("buffered-get: on_request: url: %s: range: \"%s\"", this->m_url.c_str(), range->c_str());
				bool ok = false;

				this->m_ranges = srange_info::parse(*range, &ok);
			}
		}

		if (this->m_ranges.empty()) {
			srange_info info;
			info.offset = 0;

			this->m_ranges.push_back(info);
		}

		if (this->m_ranges.front().offset) {
			auto &info = this->m_ranges.front();
			m_prefetched_offset = *info.offset;

			size_t size2read = this->m_buffer_size;
			if (info.size)
				size2read = std::min(size2read, *info.size);

			m_session->read_data(m_key, *info.offset, size2read).connect(
					std::bind(&on_get::on_first_chunk_read, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} else {
			m_session->lookup(m_key).connect(
					std::bind(&on_get::on_lookup_finished, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		}
	}

private:
	std::unique_ptr<elliptics::session> m_session;

	elliptics::data_pointer m_prefetched_data;
	size_t m_prefetched_offset = 0;

	elliptics::key m_key;

	void on_lookup_finished(const elliptics::sync_lookup_result &result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("buffered-get: on_lookup_finished: url: %s: error: %s",
					this->m_url.c_str(), error.message().c_str());

			if (error.code() == -ENOENT) {
				this->send_reply(swarm::http_response::not_found);
				return;
			} else {
				this->send_reply(swarm::http_response::internal_server_error);
				return;
			}
		}

		const elliptics::lookup_result_entry &entry = result[0];
		const auto file_info = entry.file_info();
		this->m_total_size = file_info->size;
		this->m_timestamp = file_info->mtime;

		auto err = this->fill_ranges();
		if (err) {
			NLOG_ERROR("buffered-get: on_lookup_finished: url: %s: ranges filling error: %s",
					this->m_url.c_str(), err.message().c_str());
			this->send_reply(swarm::http_response::requested_range_not_satisfiable);
			return;
		}
	}

	void on_first_chunk_read(const elliptics::sync_read_result &result, const elliptics::error_info &error) {
		if (error) {
			NLOG_ERROR("buffered-get: on_first_chunk_read: url: %s: error: %s",
					this->m_url.c_str(), error.message().c_str());

			auto ec = boost::system::errc::make_error_code(static_cast<boost::system::errc::errc_t>(-error.code()));
			this->reply()->close(ec);
			return;
		}

		const elliptics::read_result_entry &entry = result[0];
		const elliptics::data_pointer &file = entry.file();

		m_prefetched_data = file;

		struct dnet_io_attr *io = entry.io_attribute();
		this->m_total_size = io->total_size;
		this->m_timestamp = io->timestamp;

		NLOG_NOTICE("buffered-get: on_first_chunk_read: url: %s: "
				"prefetched_offset: %lu, prefetched_size: %lu, total_size: %ld",
				this->m_url.c_str(), m_prefetched_offset, (unsigned long)file.size(), this->m_total_size);


		// if this is the very first read, it is possible that some ranges are opened, for example 500- or -300,
		// we have to update all of them and will generate IO devices to read data and to host headers/delimiters
		auto err = this->fill_ranges();
		if (err) {
			NLOG_ERROR("buffered-get: on_read_first: url: %s: ranges filling error: %s",
					this->m_url.c_str(), err.message().c_str());
			this->send_reply(swarm::http_response::requested_range_not_satisfiable);
			return;
		}
	}

	/*
	 * @offset is offset within given key to start reading @size bytes
	 */
	void add_async(size_t offset, size_t size) {
		if (m_prefetched_data.empty()
			|| m_prefetched_offset >= offset + size
			|| m_prefetched_offset + m_prefetched_data.size() <= offset) {
			this->add_async_raw(offset, size);
			return;
		}

		if (offset < m_prefetched_offset) {
			const size_t delta = std::min(size, m_prefetched_offset - offset);

			this->add_async_raw(offset, delta);

			size -= delta;
			offset += delta;
		}

		if (!size)
			return;

		elliptics::data_pointer data;

		if (offset > m_prefetched_offset) {
			data = m_prefetched_data.slice(offset - m_prefetched_offset, size);
		} else {
			data = m_prefetched_data.slice(0, size);
		}

		if (!data.empty()) {
			offset += data.size();
			size -= data.size();

			this->add_buffer(std::move(data));
		}

		if (size) {
			this->add_async_raw(offset, size);
		}
	}
	void add_async_raw(size_t offset, size_t size) {
		this->m_devices.emplace_back(new async_device(*m_session, m_key, offset, size));
	}
};

template <typename Server>
class on_static : public on_read_base<Server, on_static<Server>>
{
public:
	on_static() : m_fd(-1) {}
	~on_static() {
		if (m_fd >= 0)
			close(m_fd);
	}

	virtual void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
		const auto &query = req.url().query();
		this->m_url = req.url().to_human_readable();

		(void) buffer;

		int err;
		m_key = req.url().path().substr(1);

		boost::filesystem::path p(m_key);
		boost::filesystem::path absolute = boost::filesystem::absolute(p, "/");

		std::string secure_path = this->server()->static_root_dir() + "/" + absolute.native();
		m_fd = open(secure_path.c_str(), O_RDONLY);
		if (m_fd < 0) {
			err = -errno;

			NLOG_INFO("static-get: on_request: url: %s: key: %s: could not open file: %s [%d]",
					this->m_url.c_str(), m_key.c_str(), strerror(-err), err);

			if (err == -ENOENT) {
				this->send_reply(swarm::http_response::not_found);
			} else {
				this->send_reply(swarm::http_response::bad_request);
			}

			return;
		}

		struct stat st;
		err = fstat(m_fd, &st);
		if (err < 0) {
			err = -errno;

			NLOG_INFO("static-get: on_request: url: %s: key: %s: could not stat file: %s [%d]",
					this->m_url.c_str(), m_key.c_str(), strerror(-err), err);

			this->send_reply(swarm::http_response::internal_server_error);
			return;
		}

		this->m_total_size = st.st_size;
		this->m_timestamp.tsec = st.st_mtim.tv_sec;
		this->m_timestamp.tnsec = st.st_mtim.tv_nsec;

		NLOG_INFO("static-get: on_request: url: %s, key: %s -> %s",
				this->m_url.c_str(), m_key.c_str(), secure_path.c_str());

		if (query.has_item("offset") || query.has_item("size")) {
			srange_info info;
			try {
				info.offset = query.item_value("offset", 0lu);
				info.size = query.item_value("size", 0lu);
			} catch (const std::exception &e) {
				NLOG_ERROR("buffered-get: on_request: url: %s: invalid size/offset parameters: %s",
						this->m_url.c_str(), e.what());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}

			this->m_ranges.push_back(info);
		} else {
			auto range = this->request().headers().get("Range");
			if (range) {
				NLOG_INFO("static-get: on_request: url: %s: range: \"%s\"", this->m_url.c_str(), range->c_str());
				bool ok = false;

				this->m_ranges = srange_info::parse(*range, &ok);
			}
		}

		if (this->m_ranges.empty()) {
			srange_info info;
			info.offset = 0;
			info.size = this->m_total_size;

			this->m_ranges.push_back(info);
		}


		auto einfo = this->fill_ranges();
		if (einfo) {
			NLOG_ERROR("static-get: on_request: url: %s: ranges filling error: %s",
					this->m_url.c_str(), einfo.message().c_str());
			this->send_reply(swarm::http_response::requested_range_not_satisfiable);
			return;
		}
	}

	void add_async(size_t offset, size_t size) {
		this->m_devices.emplace_back(new fs_device(m_fd, offset, size));
	}

private:
	std::string m_key;
	int m_fd;
};

}} // namespace ioremap::nullx
