#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "../../lib/allocator.h"
#include "../../lib/socket/rrr_socket.h"
#include "../../lib/zlib/rrr_zlib.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("zlibtest");

static const char *testdata_input_file = "./testdata";
static const char *testdata_output_File = "./testdata.gz";

int main (int argc, const char **argv) {
	int ret = EXIT_SUCCESS;

	(void)(argc);
	(void)(argv);

	char *data_input = NULL;
	char *data_output = NULL;

	rrr_biglength data_input_size;
	rrr_biglength data_output_size;

	rrr_allocator_init();

	if (rrr_socket_open_and_read_file (
			&data_input,
			&data_input_size,
			testdata_input_file,
			0,
			0
	)) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_socket_open_and_read_file (
			&data_output,
			&data_output_size,
			testdata_input_file,
			0,
			0
	)) {
		ret = EXIT_FAILURE;
		goto out;
	}


	out:
	RRR_FREE_IF_NOT_NULL(data_input);
	RRR_FREE_IF_NOT_NULL(data_output);
	rrr_socket_close_all();
	rrr_allocator_cleanup();
	return ret | EXIT_FAILURE;
}
