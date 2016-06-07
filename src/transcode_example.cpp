#include "nullx/transcode.hpp"

#include <boost/program_options.hpp>

#include <iostream>

using namespace ioremap;

int main(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	std::string input_file, output_file;
	bpo::options_description tr_options("Transcoder example options");
	tr_options.add_options()
		("input", bpo::value<std::string>(&input_file)->required(), "input file to transcode")
		("output", bpo::value<std::string>(&output_file)->required(), "output file (H264/AAC transcoded)")
		("help", "this help")
		;

	bpo::options_description cmdline_options;
	cmdline_options.add(tr_options);

	bpo::variables_map vm;

	try {
		bpo::store(bpo::command_line_parser(argc, argv).options(cmdline_options).run(), vm);

		if (vm.count("help")) {
			std::cout << cmdline_options << std::endl;
			return 0;
		}

		bpo::notify(vm);
	} catch (const std::exception &e) {
		std::cerr << "Invalid options: " << e.what() << "\n" << cmdline_options << std::endl;
		return -1;
	}

	av_register_all();
	avfilter_register_all();

	nullx::transcoder tr;
	int err = tr.transcode(input_file, output_file);

	std::cout << "Transcoded: " << input_file << " -> " << output_file << ", status: " << err << std::endl;
	return 0;
}
