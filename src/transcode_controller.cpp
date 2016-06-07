#include "nullx/transcode.hpp"

namespace ioremap { namespace nullx {

transcode_controller::transcode_controller(int num_workers):
	m_ctl(num_workers, std::bind(&transcode_controller::transcode, this, std::placeholders::_1))
{
}

ribosome::fpool::message transcode_controller::transcode(const ribosome::fpool::message &msg)
{
	std::string input_file(msg.data.get(), msg.header.size);
	std::string output_file = input_file + ".mp4";

	transcoder tr;
	int err = tr.transcode(input_file, output_file);
	if (err) {
		ribosome::fpool::message reply = ribosome::fpool::message::copy_header(msg);
		reply.header.status = err;
		return reply;
	}

	ribosome::fpool::message reply(output_file.size());
	reply.header = msg.header;
	reply.header.size = output_file.size();
	reply.header.status = 0;

	return reply;
}

}} // namespace ioremap::nullx
