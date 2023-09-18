import glob
import os
import re
import shutil
from pathlib import Path

counter = 1


def safety_list(lyst: list):
	if lyst is not None and lyst:
		return lyst
	else:
		return []


def chain_get(attribute: list, obj, pillowGet: bool = False):
	output = None
	attribute.reverse()
	if pillowGet:
		output = obj

	while obj:
		obj = safe_get(attribute[-1], obj)
		attribute.pop()

		if pillowGet and obj:
			output = obj
		if not attribute:
			return output or obj

	return output


def safe_get(attribute, obj, _default=None):
	if hasattr(obj, attribute) and getattr(obj, attribute) is not None:
		return getattr(obj, attribute)
	else:
		return _default


def new_match(name: str, dyct: dict) -> str:
	if any(lambda obj: compare(name, obj) for value in dyct.values()):
		return name
	else:
		return None


def match(lib: dict, dyct: dict) -> str:
	name = get_fully_qualified_name(lib)
	if any(lambda obj: compare(name, obj) for value in dyct.values()):
		return name
	elif any(lambda obj: compare(get_fully_qualified_name(lib, True), obj)
			 for value in dyct.values()):
		return name
	else:
		return None


def get_fully_qualified_file_name(base_path: str):

	def decipher_name(file: str) -> str:
		if base_path is not None and base_path != '' and os.path.abspath(
				file).startswith(base_path):
			return f"{os.path.basename(os.path.normpath(base_path))}.{os.path.abspath(file).replace(base_path, '').replace(os.sep, '.').replace('.py', '')}".replace(
				"..", ".")
		else:
			return os.path.basename(file).replace('.py', '')

	return decipher_name


def get_fully_qualified_name(lib: dict,
							 full: bool = False,
							 use_class_name: bool = False) -> str:
	return f"{lib['imports'] if not use_class_name or not 'class_name' in lib else lib['class_name']}" + full * f".{lib['criteria']}"


def get_fully_qualified_name_curry(imports: str):

	def curry_prep(lib: dict, full: bool = False, use_class_name: bool = False):

		try:
			if lib['criteria'].startswith(':='):
				return lib['criteria'][2:]
			else:
				return f"{imports if not use_class_name or not 'class_name' in lib else lib['class_name']}" + full * f".{lib['criteria']}"
		except Exception as e:
			# print(e)
			pass

	return curry_prep


def retrieve_files(path=os.path.abspath(os.curdir),
				   exclude_expressions=[]):

	if len(of_list(exclude_expressions))> 0:
		regex = re.compile(" | ".join(map(str.strip,exclude_expressions)), re.X|re.I)
		include = lambda file_path: not bool(regex.search(file_path))
	else:
		include = lambda _: True

	if os.path.isfile(path):
		return [path] if include(path) else []

	return [
		str(Path(filename).resolve())
		for filename in glob.iglob(os.path.join(path, '**/*.py'), recursive=True)
		if include(filename)
	]


def flatten_list(lyst: list) -> list:
	if not lyst:
		return []

	big_list = len(lyst) > 1
	if isinstance(lyst[0], list):
		return flatten_list(lyst[0]) + (big_list * flatten_list(lyst[1:]))
	else:
		return [lyst[0]] + (big_list * flatten_list(lyst[1:]))


def compare(regex,
			string,
			starts_with: bool = False,
			strip_start: bool = False,
			open_front: bool = False,
			open_back: bool = False):
	"""
	Added a ^ and $ to encapsulate the beginning and end of the string
	"""
	'''
	re.search(regex, str(string).replace('"', '').replace("'", "")) is not None
	or
	'''
	if regex in ['*', string]:
		return True
	not_starts_with, not_ends_with = not str(regex).startswith(
		"*") and not open_front, not str(regex).endswith("*") and not open_back
	return re.search(
		f"{'^' * (not_starts_with and not strip_start)}{regex}{'$' * not_ends_with}",
		string) is not None or (starts_with * string.startswith(regex))


def of_list(obj: object, functor=None, group_nodeList=True) -> list:
	"""
	Creating a list out of an object, and potentially applying a functor

	@param obj: object (single or list)
	@param functor: function (lambda type)
	@return: list
	"""
	if not functor or functor is None:

		def functor(x):
			return x

	if isinstance(obj, list):
		return [functor(x) for x in obj]
	else:
		return [functor(obj)]


def custom_perm(variants):
	import itertools as it

	varNames = sorted(variants)
	return [
		dict(zip(varNames, prod))
		for prod in it.product(*(variants[varName] for varName in varNames))
	]


def to_string(object,
			  prefix: str = None,
			  suffix: str = None,
			  lambd=None) -> str:
	if not prefix:
		prefix = ""
	if not suffix:
		suffix = ""
	if not lambd:

		def lambd(x):
			return x

	def replace_last(string, old, new):
		return new.join(str(string).rsplit(old, 1))

	if isinstance(object, dict):
		output = "{"
		for key, value in object.items():
			output += f"""{prefix}\"{lambd(key)}\"{suffix}: {to_string(value, prefix, suffix, lambd)},\n"""
		output = replace_last(output, ",", "")
		output += "}"
	elif isinstance(object, list):
		output = "["
		for value in object:
			output += f"""{to_string(value, prefix, suffix, lambd)},\n"""
		output = replace_last(output, ",", "")
		output += "]"
	elif hasattr(object, "toDict"):
		output = to_string(object.toDict(), prefix, suffix, lambd)
	elif hasattr(object, "toString"):
		output = object.toString(prefix, suffix, lambd)
	else:
		output = f"\"{prefix}{lambd(object)}{suffix}\""

	return output


def try_delete(path):
	try:
		if os.path.exists(path):
			if os.path.isdir(path):
				shutil.rmtree(path, ignore_errors=True)
			else:
				os.remove(path)
		return path
	except Exception as e:
		pass
	return None
