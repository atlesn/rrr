# Command Line Parser
Command line parser for C. Parse argc and argv and store `argument=value` pairs
for later retrieval or converting to numeric types.

# Usage
1. Have a look at cmdline.h for function overview and syntax
2. Allocate memory by defining `struct cmd_data data;`
3. Parse the command line with `cmd_parse()`. If we find argument=value pairs, these
   can be retrieved with `cmd_get_value()` which also returns `NULL` if the argument is
   not found.
4. The first argument is always considered to be a command. Check its value with
   cmd_match() which returns 0 on a match.
5. Use `cmd_get_argument()` to retrieve an argument at a specific location.
6. Run `cmd_convert_XXX()` to convert a string to different numeric types. These
   functions returns 0 on success and 1 on failure.
7. Retrieve numeric values by using the corresponding `cmd_get_XXX()`-functions. These
   will crash the program if you haven't first converted the values.
8. Use `cmd_get_last_argument()` to retrieve the last unused argument for instance after
   several argument=value-pairs already retrieved with the other functions.
9. Run `cmd_check_all_args_used()` to make sure there aren't any more arguments we haven't
   used. Returns 0 on success and 1 on failure.

# Configuration
`cmd_parse()` takes a configuration argument with parameters which can be ORed together:
- `CMD_CONFIG_DEFAULTS`: If left alone, defaults are used
- `CMD_CONFIG_NOCOMMAND`: Treat the first argument as any other parameter instead of command

# Memory usage
Memory may be tuned with the parameters `CMD_MAXIMUM_CMDLINE_ARGS` and `CMD_MAXIMUM_CMDLINE_ARG_SIZE`. Memory
usage on the stack (or heap if malloc'ed) is `CMD_MAXIMUM_CMDLINE_ARGS * CMD_MAXIMUM_CMDLINE_ARG_SIZE * 2`
along with a set of numeric types for every argument. Command Line Parser uses no dynamic memory.

If arguments exceed the limits, the program crashes. Only arguments containing `=`
have this size limit, the other arguments are not copied but pointed to.

If the memory pointed to by `*argv[]` argument for `cmd_parse()` is deallocated, no more functions
should be used before `cmd_parse()` is called again.

# Author
Atle Solbakken atle@goliathdns.no
github.com/atlesn
