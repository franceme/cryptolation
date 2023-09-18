import os
from abc import ABC, abstractmethod
import datetime

#region Src
try:
	import src.utils
	from src.output_routing import vuln
	from src.output_routing.vuln import Klass
except Exception as e:
	from output_routing import vuln
	from output_routing.vuln import Klass
	import utils
	#print(e)
	pass
#endregion


def fancy_date(date: datetime.datetime):
	return date.strftime("%a %b %d %H:%M:%S %Z %Y")


class file_scan_struct(object):

	def __init__(self, overlord, file: str, dedup: bool = True):
		self.file = file
		self._imports = {}
		self._imports_num = 0
		self.vuln = []
		self.vuln_num = 0
		self.run_time = None
		self.overlord = overlord
		self.qual_name = self.overlord.qualify(self.file)
		self.dedup = dedup

	def __enter__(self):
		import time
		self.start = True
		self.end = False
		self.start_date = datetime.datetime.now(datetime.timezone.utc)
		self.start_time = time.time()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		import time
		self.end_time = time.time()
		self.end_date = datetime.datetime.now(datetime.timezone.utc)
		self.run_time = self.end_time - self.start_time
		self.end = True
		self.overlord += self
		return self

	def __iadd__(self, object):
		if isinstance(object, Klass):
			object.fully_qualified_loc = f"{self.qual_name}:{object.line}"

			if not self.dedup:
				self.vuln += [object]
				self.vuln_num = self.vuln_num + 1
			elif (len(self.vuln) == 0 or
				  not any(x.is_(object) for x in self.vuln) and
				  not any(x.is_of(object) for x in self.vuln)):
				self.vuln += [object]
				self.vuln_num = self.vuln_num + 1
		elif isinstance(object, dict):
			self._imports = {**self.imports, **object}
		return self

	def __len__(self):
		return len(self.vuln)

	def __getitem__(self, sliced):
		if isinstance(sliced, int):
			return self.vuln[sliced]
		else:
			return self.toDict[sliced]

	def add_vuln(self, vuln):
		if len(self.vuln) <= len(
				list(filter(lambda itym: itym is vuln, self.vuln))):
			self.vuln += [vuln]
			self.vuln_num = self.vuln_num + 1

	def imports(self, object: dict = None):
		if object:
			self._imports = object
			self._imports_num = len(object.keys())
		return object

	def imports_num(self) -> int:
		return self._imports_num

	@property
	def toDict(self):
		return {
			'File Name': self.file,
			'Fully Qualified Path': self.qual_name,
			'Imports': self._imports,
			'Imports Lite': self._imports_num,
			'Vulnerabilities': self.vuln,
			'Vulnerabilities Lite': len(self.vuln),
			'Start Time': fancy_date(self.start_date),
			'Duration Time': self.run_time,
			'End Time': fancy_date(self.end_date),
		}

	@property
	def toString(self):
		raw_output = self.toDict
		raw_output['Vulnerabilities'] = [
			vuln.base_str for vuln in raw_output['Vulnerabilities']
		]
		return str(raw_output)


class Structure(ABC):

	def __enter__(self):
		self.output_writer = open(self.output_file, "w+")
		self.writeHeader()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		import time
		self.end_date = datetime.datetime.now(datetime.timezone.utc)
		self.end_time = time.time()

		self.writeFooter()
		self.return_output = self.dict
		self.output_writer.close()
		self.return_output = self.dict
		return None

	def __init__(self,
				 path,
				 output_type,
				 output_name: str = "TEMP",
				 open_writer: bool = True,
				 all_files: bool = False):
		super().__init__()
		import time

		self.start_date = datetime.datetime.now(datetime.timezone.utc)
		self.start_time = time.time()
		self.path = os.path.abspath(path)
		self.qualify = src.utils.utils.get_fully_qualified_file_name(
			'' if os.path.isfile(self.path) else self.path)
		self.start = False
		self._end_time = None
		self._duration = None
		self._vuln_count = 0
		self._import_count = 0
		self.output_type = output_type
		self.output_file = output_name
		self.all_files = all_files

		# region Src
		try:
			from src.output_routing.management import default
		except Exception as e:
			# print(e)
			pass
		try:
			from output_routing.management import default
		except Exception as e:
			# print(e)
			pass
		# endregion

		if open_writer:
			self.output_writer = open(self.output_file, "w+")

	def __iadd__(self, object: file_scan_struct):
		if object is not None and (len(object) > 0 or self.all_files):
			self.add_issue(object)
			self._vuln_count += len(object['Vulnerabilities'])
			self._import_count += len(object['Imports'])
		return self

	def append(self, string_type):
		# region Local ofList imports
		try:
			from src.utils.utils import of_list
		except Exception as e:
			pass
		try:
			from utils.utils import of_list
		except Exception as e:
			pass
		[
			self.output_writer.write(f"{string}\n")
			for string in of_list(string_type)
		]

	@property
	def dict(self):
		import platform, multiprocessing
		platform_name = platform.uname()

		return {
			'Path': self.path,
			'Output File': self.output_file,
			'Output Type': self.output_type,
			'Start': self.start,
			'Start Time': fancy_date(self.start_date),
			'End Time': fancy_date(self.end_date),
			'Duration': self.duration,
			'System': platform_name.system,
			'Release': platform_name.release,
			'Version': platform_name.version,
			'Processor': platform_name.processor,
			'Cores': multiprocessing.cpu_count(),
			'Vulnerabilities': self.vulnerabilities
		}

	@property
	def duration(self):
		if self._duration is None:
			self._duration = self.end_time - self.start_time
		return self._duration

	@property
	def vulnerabilities(self):
		if self._vuln_count is None:
			self._vuln_count = sum(
				len(value['Vulnerabilities']) for value in self.files)
		return self._vuln_count

	@property
	def imports(self):
		if self._import_count is None:
			self._import_count = sum(
				len(value['Imports'].keys()) for value in self.files)
		return self._import_count

	@abstractmethod
	def writeHeader(self):
		pass

	@abstractmethod
	def writeFooter(self):
		self.output_writer.close()

	@abstractmethod
	def add_issue(self, object: file_scan_struct):
		pass

	@abstractmethod
	def escape_string(self, string: object):
		pass
