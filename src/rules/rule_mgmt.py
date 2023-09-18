import astroid

try:
	import src.rules.rule_source as ru
	from src.node_utilities.node_utils import get_args, full_context, is_uninferable, retrieve_specific_body
	from src.output_routing import vuln, management
	from src.output_routing.base_structure import file_scan_struct, Structure
	from src.utils import Conversing
	from src.utils.Conversing import translator
	from src.utils.utils import retrieve_files, of_list, safe_get, get_fully_qualified_name_curry, new_match, flatten_list, \
	compare
except Exception as e:
	import rules.rule_source as ru
	from node_utilities.node_utils import get_args, full_context, is_uninferable, retrieve_specific_body
	from output_routing import vuln
	from output_routing.base_structure import file_scan_struct, Structure
	from output_routing.structures import management
	from utils import Conversing
	from utils.Conversing import translator
	from utils.utils import retrieve_files, of_list, safe_get, get_fully_qualified_name_curry, new_match, flatten_list, \
	 compare


def handle_search(path: str,
				  rule_file=None,
				  output_file: str = "temp_file",
				  output_type: str = "csv",
				  exclude_paths=[],
				  all_files=False):

	with management.get_structure(output_type)(path,
											   output_file,
											   all_files=all_files) as handler:
		rules, secure_values = ru.load(rule_file)
		print("[", end='', flush=True)
		for foil in retrieve_files(path, exclude_paths):
			handler += search(handler, foil, rules, secure_values)
			print(".", end='', flush=True)
		print("]")
	return 0


def search(overlord: Structure, file, rules=None, secure_values=None) -> None:
	with file_scan_struct(overlord, file) as file_reader:
		try:
			tree = Conversing.translator(file)

			for import_name in set(tree.get_shared_imports(rules)):
				imports = file_reader.imports(tree.imports)
				_get_qual = get_fully_qualified_name_curry(import_name)

				for lib in rules[import_name]:
					file_fully_qualified_name = new_match(
						_get_qual(lib, True, False), imports)
					if file_fully_qualified_name:

						found_nodes = None
						try:
							found_nodes = tree.search(
								lib['target'] if 'target' in lib else _get_qual(
									lib, True, 'target' not in lib),
								endsWith='builder' in lib,
								searchForTarget='target' in lib)
						except Exception as e:
							pass

						for found_node in found_nodes:
							prep_string = f"the library {_get_qual(lib, True)} @ line:{found_node.lineno}"
							lib['imports'] = import_name
							rule_num = lib['group']

							msg, name, severity = ru.unwravel(rule_num)
							if 'arguments' in lib and 'target' not in lib:
								handle_arguments(tree, found_node, lib,
												 secure_values, prep_string,
												 file_reader,
												 file_fully_qualified_name,
												 file, name, msg, rule_num,
												 severity)
							elif 'target' in lib and lib['criteria'] == '*':
								map_results_to_output(
									file_reader=file_reader,
									file_fully_qualified_name=
									file_fully_qualified_name,
									prep_string=prep_string,
									message=f"Using {prep_string}",
									file=file,
									msg=msg,
									name=name,
									context_lambda=None,
									rule_num=rule_num,
									severity=severity,
									line=found_node.lineno,
									found_node=found_node,
									results=None)
							elif 'target' in lib:
								try:
									for target in of_list(found_node.targets):
										if hasattr(target, 'expr'):
											create = lambda pytype: f"{pytype}.{target.attrname}"
											if any([
													compare(
														lib['criteria'],
														qual_name)
													for qual_name in of_list([
														str(x.pytype()) for x in
														target.expr.inferred()
													], create)
											]):
												map_results_to_output(
													file_reader=file_reader,
													file_fully_qualified_name=
													file_fully_qualified_name,
													prep_string=prep_string,
													message=
													f"Using {prep_string}",
													file=file,
													msg=msg,
													name=name,
													context_lambda=None,
													rule_num=rule_num,
													severity=severity,
													line=found_node.lineno,
													found_node=found_node,
													results=None)

										elif isinstance(target.parent,
														astroid.nodes.Assign):
											results = evaluate_conditions(
												tree, target, lib,
												secure_values)
											if results:

												def context_lambda():
													return results

												map_results_to_output(
													file_reader=file_reader,
													file_fully_qualified_name=
													file_fully_qualified_name,
													prep_string=prep_string,
													results=results,
													file=file,
													found_node=found_node,
													msg=msg,
													name=name,
													context_lambda=
													context_lambda,
													rule_num=rule_num,
													severity=severity)

								except Exception as e:
									pass
							else:
								map_results_to_output(
									file_fully_qualified_name=
									file_fully_qualified_name,
									message=f"Using {prep_string}",
									file=file,
									line=found_node.lineno,
									msg=msg,
									name=name,
									rule_num=rule_num,
									severity=severity,
									file_reader=file_reader,
									prep_string=prep_string,
									results=None,
									found_node=found_node,
									context_lambda=None)

		except Exception as E:
			pass

		return


def handle_arguments(tree, found_node, lib, secure_values, prep_string,
					 file_reader, file_fully_qualified_name, file, name, msg,
					 rule_num, severity):
	if tree.determine_hierarchy_lvl_to_node(found_node) == 0:
		results = evaluate_conditions(tree, found_node, lib, secure_values)
		if results:

			def context_lambda():
				return results

			map_results_to_output(file_reader, file_fully_qualified_name,
								  prep_string, results, file, found_node, msg,
								  name, context_lambda, rule_num, severity)
	else:
		parent_def = tree.get_parent(found_node, astroid.FunctionDef)
		"""TODO - Performance multi-thread this?"""
		for (discovered, discovered_method) in tree.find_calls(parent_def):

			expanded_calls = tree.expand_function_calls(discovered,
														discovered_method)
			(context_runs, context_details) = full_context(expanded_calls)

			for context, details in zip(context_runs, context_details):
				"""
				Put in line search for found value in context
				identify found_node from within context, pass it to evaluate conditions
				"""
				identified_node = tree.identify_method(context, found_node)
				get_callable_method = tree.retrieve_method_type(identified_node)

				results = evaluate_conditions(context, get_callable_method, lib,
											  secure_values)

				def context_lambda():
					context_detail = {}
					for method_context in details:
						method_context_func_name = method_context['func'].split(
							':')[1]
						for method_context_value in method_context[
								'args'].values():
							(name, _raw_value_) = method_context_value
							if method_context_func_name not in context_detail:
								context_detail[method_context_func_name] = {
									name.name: _raw_value_.value
								}
							else:
								context_detail[method_context_func_name][
									name.name] = _raw_value_.value
					return context_detail

				map_results_to_output(file_reader, file_fully_qualified_name,
									  prep_string, results, file, found_node,
									  msg, name, context_lambda, rule_num,
									  severity)


def map_results_to_output(file_reader,
						  file_fully_qualified_name,
						  prep_string,
						  results,
						  file,
						  found_node,
						  msg,
						  name,
						  context_lambda,
						  rule_num,
						  severity,
						  message=None,
						  line: int = None):
	if context_lambda is None:

		def context_lambda():
			return None

	file_reader += vuln.Klass(
		type=file_fully_qualified_name,
		message=message if message is not None else
		f"{''.join([line['Error String'] for line in results])} "
		f"Using {prep_string}",
		file=file,
		line=line if line is not None else found_node.lineno,
		matched=msg,
		rule=name,
		rule_num=rule_num,
		severity=severity,
		context=context_lambda())


def loop_thru_args(lib, argz, arg_name, secure_values, value_comprehension,
				   pretty_comprehension, is_target_check,
				   inner_value_loop) -> dict:
	output = {}
	for verify in lib['arguments']:
		"""
		Check this for include_int
		"""
		includes, verify['live_type'] = True, verify['type']
		if verify['live_type'].startswith('include'):
			includes = False
			verify['live_type'] = verify['live_type'].split('_')[-1]

		for idx, (arg_key, arg_value) in enumerate(argz().items()):
			if not includes and (arg_key == verify.get(
					'name', None)) or (idx == verify.get('index', None)):
				includes = True

			_raw_target_check = is_target_check(arg_key, verify)
			if _raw_target_check:
				for val in inner_value_loop(arg_value):

					working_value = arg_key if arg_value is None else val

					if is_uninferable(working_value):
						debug = 00
					else:
						error_string = ru.rule_check(
							verify, value_comprehension(working_value),
							secure_values)
						if error_string:
							output = {
								'Error String':
									error_string,
								'Variable Name':
									pretty_comprehension(arg_key),
								'Inferred Variable Value':
									arg_value
									or value_comprehension(working_value)
							}
		if not includes:
			output = {
				'Error String':
					"Variable is not included and the Inferred value is not set",
				'Variable Name':
					pretty_comprehension(safe_get('name', verify)),
				'Inferred Variable Value':
					f"Variable should be set to {verify['type']}"
			}
	return output or None


def evaluate_conditions(tree: Conversing.translator, found_node, lib: dict,
						secure_values) -> list:
	if found_node is None:
		return []

	import astroid
	output = []

	if isinstance(safe_get('value', found_node), astroid.node_classes.Name):

		temp_output = loop_thru_args(
			lib=lib,
			argz=lambda: {value: None for value in found_node.value.inferred()},
			arg_name=lambda arg_name_value: found_node.value,
			secure_values=secure_values,
			value_comprehension=lambda raw_value: raw_value.qname(),
			pretty_comprehension=lambda founded_node: found_node.value.
			as_string(),
			is_target_check=lambda x, y: True,
			inner_value_loop=lambda value: [value])
		if temp_output:
			output += [temp_output]

	else:

		if lib['criteria'] == '*':
			arguments = get_args(found_node)
		else:
			if safe_get('args', found_node):
				arguments = get_args(found_node)
			else:
				arguments = get_args(
					retrieve_specific_body(found_node, lib['criteria']))

		def is_target(arg_name, verify) -> bool:
			"""
			Returns interesting logic if the argument is being targeted.
			@return: bool
			"""

			name = arg_name.replace('_raw_argument_', '')
			return (arg_name.startswith('_raw_argument') and
					(('index' in verify and verify['index'] == int(name)))) or (
						'name' in verify and verify['name'] == name)

		def inner_loop(arg_value):

			if isinstance(arg_value, astroid.ClassDef):
				output = arg_value.name
				rent = safe_get('parent', arg_value)
				if rent:
					output = rent.name + "." + output
				return output
			if hasattr(arg_value, 'value'):
				return str(arg_value.value).split("(")[0]
			elif hasattr(arg_value, 'pytype'):
				return arg_value.pytype()
			else:
				return arg_value

		temp_output = loop_thru_args(
			lib=lib,
			argz=lambda: arguments,
			arg_name=lambda arg_key: arg_key,
			secure_values=secure_values,
			value_comprehension=lambda working_value: working_value,
			pretty_comprehension=lambda arg_key: arg_key,
			is_target_check=is_target,
			inner_value_loop=lambda arg_value_value:
			[inner_loop(x) for x in arg_value_value if x is not None])
		if temp_output:
			output += [temp_output]

	return output
