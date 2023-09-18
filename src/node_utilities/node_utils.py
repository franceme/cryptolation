from typing import Tuple

import astroid
#region Src
try:
	from src.utils.utils import flatten_list, custom_perm, safe_get, chain_get
except Exception as e:
	from utils.utils import flatten_list, custom_perm, safe_get, chain_get
	#print(e)
	pass
#endregion


def get_pretty_infer_names_base(node: astroid.Expr,
								filter_name: str = 'builtins'):
	return [
		x.pytype()
		for x in node.inferred()
		if not str(x.pytype()).startswith(filter_name) and not is_uninferable(x)
	]


def full_context(depth, output: [] = []) -> Tuple[list, list]:
	from copy import deepcopy as dc

	class store:

		def __init__(self):
			self.variables = {}
			self.functions = {}

		def _store(self, obj, func=False):
			if func:
				self.functions[str(len(self.functions.keys()))] = obj
				return int(len(self.functions) - 1)
			else:
				self.variables[str(len(self.variables.keys()))] = obj
				return int(len(self.variables) - 1)

		def __call__(self, searchBy: int = None, func=False):
			if searchBy is None:
				return self.functions if func else self.variables
			elif func and str(searchBy) in self.functions:
				return self.functions[str(searchBy)]
			elif not func and str(searchBy) in self.variables:
				return self.variables[str(searchBy)]
			return None

	store = store()
	import collections
	full_args = collections.defaultdict(set)
	"""
	This next section is about computing the complicated different amount of permutations
	region perms: arg_permutations
	"""
	try:
		for function in depth:
			function['func'] = str(store._store(function['func'], func=True))
			if len(function['args']) > 0:
				for arg_key, arg_value in function['args'].items():
					full_args[f"{function['func']}:{arg_key}"] = [
						str(store._store(x)) for x in arg_value
					]
			else:
				full_args[f"{function['func']}:_None"] = [None]

	except Exception as e:
		debug = 23

	context, details = [], []

	perm_layers = custom_perm(full_args)

	for perm_layer in perm_layers:
		layer_details, top_layer = [], None
		for function_idx, function in enumerate(store(func=True)):
			str_function_idx, layer_func = str(function_idx) + ":", {}
			perm_layer_variables = [
				x.replace(str_function_idx, '')
				for x in perm_layer.keys()
				if x.startswith(str_function_idx)
			]

			layer_func['func'] = store(function_idx, func=True)
			layer_func['args'] = {}
			for key in perm_layer_variables:
				if 'None' not in key:
					full_key = f"{str_function_idx}{key}"
					layer_func['args'][key] = store(perm_layer[full_key])

			if top_layer is None:
				top_layer = {}
				top_layer['func'] = layer_func['func']
				top_layer['args'] = layer_func['args']

			layer_details += [layer_func]
		details += [layer_details]
		context += [
			setting_context_to_single_function(top_layer['func'],
											   top_layer['args'],
											   dc(layer_details)[1:])
		]

	return (context, details)


def setting_context_to_single_function(method, args, depths=[]):
	clean_body(method)
	inject_args(method, args)

	if len(depths) > 0:
		next_layer = depths.pop(0)
		found_function = [
			x for x in method.body if isinstance(x, astroid.FunctionDef) and
			x.name == next_layer['func'].name
		][0]

		if found_function and len(next_layer['args']):
			setting_context_to_single_function(found_function,
											   next_layer['args'], depths)

	return method


def clean_body(fn):
	idx_to_pop = []
	for itr, linee in enumerate(fn.body):
		lineno = linee.lineno
		if lineno:
			break
		else:
			idx_to_pop += [itr]

	idx_to_pop.reverse()
	for idx in idx_to_pop:
		fn.body.pop(idx)
	return


def inject_args(fn: astroid.nodes.FunctionDef, args_list: list):
	"""
	Needs to mimic https://tinyurl.com/python-astroid-add-local-node
	...Just From the front...
	"""

	#args_list.reverse()

	def create_assign(target, value):
		assign = astroid.nodes.Assign()
		assign.lineno = 0
		name = astroid.nodes.AssignName()
		name.name = target.name
		assign.targets = [name]
		target.parent = assign
		value.parent = assign

		if hasattr(value, 'value'):
			raw_value = value.value
		else:
			raw_value = value

		assign.value = astroid.nodes.const_factory(raw_value)

		return assign

	"""
	Don't Change this or make it break
	"""
	for name, arg in args_list.items():
		if name.startswith("idx_"):
			og_target = fn.args.args[int(name.replace("idx_", ''))]
		else:
			og_target = [x for x in fn.args.args if x.name == name][0]

		og_value = arg

		from copy import deepcopy as dc

		if isinstance(og_target, str):
			new_karg = astroid.nodes.AssignName()
			new_karg.lineno = 0
			new_karg.is_function = False
			new_karg.is_lambda = False
			new_karg.is_statement = False
			new_karg.name = og_target
			target = new_karg
		else:
			target = dc(og_target)

		assignment = create_assign(target, dc(og_value))

		fn.body.insert(0, assignment)
		assignment.parent = fn

		fn.set_local(target.name, target)

	return


def retrieve_specific_body(node: astroid.Call, string_match):
	if hasattr(node, 'value'):
		node = node.value
	elif isinstance(node, astroid.With):
		node = node.items[0][0]
	if string_match not in node.as_string():
		suffix = '.' + '.'.join(node.as_string().split('.')[1:])
		if not any([
				string_match in str(x + suffix)
				for x in get_pretty_infer_names_base(
					chain_get('func.expr'.split('.'), node, True)) or []
		]):
			return None

	if isinstance(safe_get('func', node), astroid.Name) and isinstance(
			node, astroid.Call) and len(safe_get('args', node, [])) == 1:
		return retrieve_specific_body(node.args[0], string_match)
	elif hasattr(node, 'func'):

		def continuous_lookup(node: astroid):
			if safe_get('attrname', node) == string_match or safe_get(
					'name', node) == string_match or safe_get(
						'attrname', node) in string_match:
				return node
			elif hasattr(node, 'expr') and hasattr(node.expr, 'func'):
				return continuous_lookup(node.expr.func)
			else:
				return None

		return continuous_lookup(node.func)
	return None


def get_args(node) -> dict:
	output = {}
	try:
		if hasattr(node, 'value'):
			node.args = node.value.args
			node.keywords = node.value.keywords

		if isinstance(node, (astroid.Attribute, astroid.Name)):
			node.args = node.parent.args
			node.keywords = node.parent.keywords
		elif isinstance(node, astroid.nodes.AssignName):
			node.args = []
			raw = type('', (), {})()
			raw.arg = node.name
			raw.value = node.parent.value

			node.keywords = [raw]

		if node.args:
			for itr, arg in enumerate(node.args):
				"""
				if hasattr(arg, 'name'):
				   output[arg.name] = infer_value(arg)
				else:
				   output[f"_raw_argument_{itr}"] = infer_value(arg)
				"""
				output[f"_raw_argument_{itr}"] = infer_value(arg)
		if node.keywords:
			for keyword in node.keywords:
				output[keyword.arg] = infer_value(keyword)

	except Exception as e:
		debug = 23
	return output


def infer_value(node) -> list:

	def simplify(node) -> astroid.nodes.Const:
		out = astroid.nodes.const_factory(node.value.as_string())
		out.lineno = node.value.lineno
		return out

	try:
		if not hasattr(node, 'value'):
			return [
				node.as_string() if is_uninferable(x) else x
				for x in node.inferred()
			]
		if isinstance(node.value, astroid.Call):
			return [simplify(node)]
		elif isinstance(node.value, astroid.nodes.Const):
			return [node.value]
		elif isinstance(node, astroid.nodes.Const):
			return [node]
		elif isinstance(node.value, astroid.nodes.Dict):
			output = []

			def to_bool(raw_value):
				value = str(raw_value).upper()
				if "TRUE" in value:
					return "true"
				elif "FALSE" in value:
					return "false"
				else:
					return raw_value

			for temp_key, temp_value in node.value.items:
				for temp_value_infer in temp_value.inferred():
					sub_value = str(to_bool(temp_value_infer.value)).replace(
						'"', '').replace("'", "")
					output += [f"{{\"{temp_key.value}\":{sub_value}}}"]
			return output

		inferred_values = [
			infer for infer in node.value.ilookup(node.value.name)
		]
		raw_values = [infer for infer in node.value.lookup(node.value.name)[1]]
		return [
			infer if not is_uninferable(infer) else simplify(raw.parent)
			for infer, raw in zip(inferred_values, raw_values)
		]

	except astroid.exceptions.NameInferenceError as e:
		return [astroid.Unknown]
	except astroid.exceptions.InferenceError as e:
		return [node.as_string()]
	except AttributeError as e:
		try:
			return [infer for infer in node.value.inferred()]
		except Exception as e:
			return [node.arg]
	except Exception as e:
		pass


def is_uninferable(node) -> bool:
	"""
	A check whether or not the result from an Astroid's inferred value is uninferable

	:param node: an Astroid Node
	:return: bool
	"""
	return isinstance(node, (astroid.Unknown, astroid.Uninferable.__class__))
