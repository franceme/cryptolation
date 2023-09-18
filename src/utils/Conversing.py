import os
import astroid
from astroid import MANAGER as MGR

#region Src
try:
	from src.utils.utils import safe_get, compare, of_list
except Exception as e:
	from utils.utils import safe_get, compare, of_list
	#print(e)
	pass
#endregion


class translator():

	def __init__(self,
				 raw_code_or_file,
				 raw_astroid: astroid.Expr = None,
				 imports=None,
				 globals=None):
		self.baron = None
		if raw_astroid:
			self.astroid = raw_astroid
			self.imports = imports
			self.globals = globals
			self.assigns = []
			self.calls = []
			self.expr = []
		else:
			if os.path.isfile(raw_code_or_file):
				with open(raw_code_or_file) as foil:
					contents = foil.readlines()
				self.raw_code = ''.join(contents)
				self.currentName = raw_code_or_file
			else:
				self.raw_code = raw_code_or_file
				self.currentName = None

			self.imports = {}
			self.globals = []
			self.calls = []
			self.assigns = []
			self.expr = []

			def gather_nodes(node: astroid.ALL_NODE_CLASSES):
				if translator.get_parent(node).name != '':
					return node

				if isinstance(node, astroid.Global):
					self.globals += [node]
				elif isinstance(node, astroid.Call):
					self.calls += [node]
				elif isinstance(node, astroid.Assign):
					self.assigns += [node]
				elif isinstance(node, astroid.Expr):
					self.expr += [node]
				else:
					for name in node.names:
						baseName, asName = name[0], ""

						if name[1]:
							asName = name[1]
						else:
							asName = baseName.split('.')[-1]

						modName = safe_get('modname', node)
						if modName:
							baseName = f"{modName}.{baseName}"

						self.imports[asName] = baseName

				return node

			for nyode in [
					astroid.Import, astroid.ImportFrom, astroid.Global,
					astroid.Call, astroid.Assign, astroid.Expr
			]:
				MGR.register_transform(nyode, gather_nodes)

			self.astroid = astroid.parse(self.raw_code)

	@property
	def redbaron(self):
		try:
			import redbaron
		except Exception as e:
			print(e)
			pass

		if self.baron is None:
			with open(self.currentName, 'r') as reader:
				self.baron = redbaron.RedBaron(''.join(reader.readlines()))
		return self.baron

	def get_shared_imports(self, rules):
		if 'smart_imports' in self.imports.keys():
			return rules
		#region Src
		try:
			from src.utils.utils import flatten_list
		except Exception as e:
			pass
		try:
			from utils.utils import flatten_list
		except Exception as e:
			pass
		#endregion
		astroid_shared = set(
			flatten_list([
				list(filter(lambda x: y.startswith(x), rules.keys()))
				for y in self.imports.values()
			]))
		return astroid_shared

	def __getitem__(self, itemNumber: int):
		try:
			return self.astroid.body[itemNumber]
		except Exception as e:
			return None

	def __call__(self, searchBy):

		def getattr(node):
			if isinstance(searchBy, int):
				return node.lineno
			else:
				return translator.str_node(node)

		def node_search(subSearchBy, node):
			#TODO - Performance HERE
			for nyode in node.body:
				currentAttr = getattr(nyode)
				if (isinstance(searchBy, int) and currentAttr == subSearchBy
				   ) or (isinstance(searchBy, str) and
						 (currentAttr == subSearchBy or
						  currentAttr.endswith(subSearchBy))):
					return nyode
				elif ((isinstance(searchBy, int) and currentAttr < subSearchBy)
					  or True) and hasattr(nyode, 'body'):
					return node_search(subSearchBy, nyode)
				return None

		return node_search(searchBy, self.astroid)

	def search(self,
			   search_string: str,
			   endsWith: bool = False,
			   searchForTarget: bool = False):
		output = []
		# region Preparing the search_string
		if search_string.startswith("."):
			search_string = search_string.split(".")[-1]
		if search_string.startswith("*."):
			search_string = search_string.split("*.")[-1]
		# endregion

		if not searchForTarget:
			call: astroid.Call
			for call in self.calls:
				# region Creating the call_string
				call_string = call.func.as_string().split('(')[0]
				base_name = '.'.join(call_string.split('.')[:-1])

				check_name = (base_name or call_string)
				if check_name in self.imports.keys():
					call_string = f"{self.imports[check_name]}.{call_string.split('.')[-1]}"

				# endregion
				if compare(search_string,
						   call_string,
						   endsWith,
						   open_front=True,
						   open_back=True):
					output += [call]
			expr: astroid.Expr
			for expr in self.expr:
				# region Creating the call_string
				call_string = expr.as_string().split('(')[0]
				base_name = '.'.join(call_string.split('.')[:-1])

				check_name = (base_name or call_string)
				if check_name in self.imports.keys():
					call_string = f"{self.imports[check_name]}.{call_string.split('.')[-1]}"

				# endregion
				if compare(search_string,
						   call_string,
						   endsWith,
						   open_front=True,
						   open_back=True):
					output += [expr]
		else:
			assign: astroid.Assign
			for assign in self.assigns:
				if compare(search_string,
						   assign.value.as_string(),
						   endsWith,
						   open_front=True,
						   open_back=True):
					output += [assign]
					break

				for target in assign.targets:
					call_string = safe_get('name', target) or safe_get(
						'attrname', target)
					if compare(search_string,
							   call_string,
							   endsWith,
							   open_front=True,
							   open_back=True):
						output += [assign]
						break

		return output

	@staticmethod
	def get_line_number(node) -> int:
		return int(node.lineno)

	@staticmethod
	def str_node(node):
		return node.as_string()

	def determine_hierarchy_lvl_to_node(self, node):
		level, moving_node = 0, node
		while hasattr(moving_node, 'parent'):
			if isinstance(moving_node, astroid.FunctionDef):
				level += 1
			moving_node = moving_node.parent
		return level

	@staticmethod
	def get_parent(compute,
				   custom_stop=None,
				   layersToGo: int = -1,
				   before_module: bool = False) -> astroid.FunctionDef:

		if isinstance(compute, astroid.Module):
			return compute
		elif layersToGo == 0:
			return compute
		elif custom_stop and isinstance(compute, custom_stop):
			return compute
		elif safe_get('parent', compute):
			if before_module and isinstance(compute.parent, astroid.Module):
				return compute
			else:
				return translator.get_parent(compute.parent, custom_stop,
											 layersToGo - 1, before_module)
		else:
			return compute

	def find_calls(self, method: redbaron) -> list:
		output = []
		call: astroid.Call
		for call in self.calls:
			inferred_function = list(call.func.inferred())[0]
			if inferred_function.name == method.name:
				output += [(call, inferred_function)]

		return output

	@staticmethod
	def query_back(section_searching: astroid.ALL_NODE_CLASSES,
				   name_looking_for: str):

		back_node: astroid.Name
		for back_node in of_list(section_searching.previous_sibling()):
			if isinstance(back_node, astroid.Assign):
				if isinstance(name_looking_for, str):
					compare = name_looking_for
				else:
					compare = name_looking_for.value

				if back_node.targets[0].value == compare:
					return back_node
		return None

	def expand_function_calls(self, method_string, method):

		depth, iterating_func = [], method_string
		for function_call in self.recursively_get_return_graph(method):
			sub_depth = {'func': function_call, 'args': {}}

			keyword: astroid.Keyword
			for keyword in safe_get('keywords', iterating_func, []):
				sub_depth['args'][keyword.arg] = list(keyword.value.inferred())
			for idx, arg in enumerate(iterating_func.args):
				sub_depth['args'][f"idx_{idx}"] = list(arg.inferred())

			iterating_func = iterating_func.func
			depth += [sub_depth]
		depth.reverse()
		return depth

	def recursively_get_return_graph(self, function) -> list:

		#region Src
		try:
			from src.node_utilities.node_utils import general_search
		except Exception as e:
			pass
		try:
			from node_utilities.node_utils import general_search
		except Exception as e:
			pass
		#endregion
		output = []
		try:
			output += [function]
			while hasattr(function, 'parent') and not isinstance(
					function.parent, astroid.Module):
				function = function.parent
				output += [function]

		except Exception as e:
			pass
		return output

	@staticmethod
	def identify_method(tree, looking_for: astroid.ALL_NODE_CLASSES):
		lyst = tree.body
		for itr in range(len(lyst)):
			tree_node = lyst[itr]
			if tree_node.lineno == looking_for.lineno:
				return tree_node
			elif tree_node.lineno > looking_for.lineno and hasattr(
					lyst[itr - 1], 'body'):
				return translator.identify_method(lyst[itr - 1], looking_for)
		return None

	@staticmethod
	def retrieve_method_type(
			tree, looking_for: astroid.ALL_NODE_CLASSES = astroid.Call):
		if isinstance(safe_get('value', tree), looking_for):
			return safe_get('value', tree)

		lyst = safe_get('body', tree, [])
		for itr in range(len(lyst)):
			tree_node = lyst[itr]
			if isinstance(tree_node, looking_for):
				return tree_node
			elif hasattr(lyst[itr - 1], 'body'):
				return translator.identify_method(lyst[itr - 1], looking_for)
		return None
