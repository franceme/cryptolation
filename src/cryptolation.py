#!/usr/bin/python3
import os
import sys
import argparse

#region Src
try:
	from src.output_routing.management import structure
	from src.rules import rule_mgmt
	from src.information import VERSION
except Exception as e:
	from output_routing.management import structure
	from rules import rule_mgmt
	from information import VERSION
	pass
#endregion

base_name = os.path.basename(__file__)
cur_path = str(__file__).replace(f"/{base_name}", '')
NAME = base_name.replace(".py", "")


def arguments(string_set):
	parser = argparse.ArgumentParser(description=f"{NAME}:> {VERSION}")

	parser.add_argument("-v",
						"--version",
						action='store_true',
						help='Show the current version')
	parser.add_argument("-s",
						"--source",
						dest="source",
						action='store',
						type=lambda x: x if os.path.exists(x.strip()) else
						parser.error(f"Path {x} does not Exist"),
						help='The current source versions')
	parser.add_argument(
		"-r",
		"--rule",
		dest="rule",
		action='store',
		type=lambda x: x
		if (os.path.isfile(x.strip()) and x.endswith('.json')
		   ) else parser.error(f"File {x} does not exist or isn't a json file"),
		help='The extra rule path')
	parser.add_argument(
		"-o",
		"--output",
		dest="output",
		action='store',
		type=lambda x: x if (str(x).split(".")[-1] in list(structure().keys(
		))) else parser.error(f"Output {x} isn't a type output supported"),
		help=
		f"The different types of output supported: [{', '.join(list(structure().keys()))}]",
		default="raw_output.csv")
	parser.add_argument(
		"-x",
		"--exclude_paths",
		dest="exclude_paths",
		action='store',
		help="Excluding the files by providing a specific regex (ex. __init__.py or \/venv\/ for the venv folder).",
		default=[],
		nargs='+')
	parser.add_argument("-a",
						"--all_files",
						action='store_true',
						help="Print out non vulnerability files",
						default=False)

	parser = parser.parse_args(string_set)
	if os.path.exists(parser.output):
		try:
			os.remove(parser.output)
		except:
			pass

	if parser.version:
		print(f"{VERSION.strip()}")
		return 0

	return parser


def main(string):
	string = list(filter(lambda x: str(x) not in [__file__ + ".py", __file__, "cryptolation", "cryptolation.py"], string))
	args_trimmed = arguments(string)
	if isinstance(args_trimmed, int):
		return args_trimmed

	return rule_mgmt.handle_search(args_trimmed.source.strip(),
								   args_trimmed.rule,
								   args_trimmed.output.strip(),
								   args_trimmed.output.split('.')[-1],
								   exclude_paths=args_trimmed.exclude_paths,
								   all_files=args_trimmed.all_files)


def hollow_main():
	sys.exit(main(sys.argv))


if __name__ == '__main__':
	hollow_main()
