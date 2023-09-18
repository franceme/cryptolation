import sqlite3
import os
from cyclonedx import output
from cyclonedx.model import ExternalReference, ExternalReferenceType, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityRating
from cyclonedx.parser import BaseParser
import hashlib

# region Src

try:
	from src.output_routing.base_structure import Structure, file_scan_struct, fancy_date
	from src.output_routing import vuln
	from src.utils import utils
except Exception as e:
	from output_routing.base_structure import Structure, file_scan_struct, fancy_date
	from output_routing import vuln
	from utils import utils
	#print(e)
	pass
# endregion

default = 'csv'


def structure():
	return {'csv': csv, 'sql': sqlite, 'xml': sbom}


def get_structure(type: str = default):
	return structure().get(type, csv)


class csv(Structure):

	def __init__(self,
				 path,
				 outputName: str = "TEMP_FILE",
				 all_files: bool = False):
		super().__init__(path=path,
						 output_type="csv",
						 output_name=outputName,
						 all_files=all_files)

	def escape_string(self, string):
		return str(string).replace(',', ';').replace('"', "'")

	def writeHeader(self):
		self.append(','.join(self.output_structure()))

	def writeFooter(self):
		self.output_writer.close()

	# region CreateRow Method
	@staticmethod
	def create_row(Fully_Qualified_Name="",
				   File_Name="",
				   Number_of_Imports="",
				   Time_Taken="",
				   MCC="",
				   IsVuln="",
				   Fully_Qualified_Loc="",
				   Type="",
				   Message="",
				   File="",
				   Line="",
				   Matched="",
				   Rule="",
				   Rule_Number="",
				   Severity="",
				   Context=""):
		sub = [
			Fully_Qualified_Name, File_Name, Number_of_Imports, Time_Taken, MCC,
			IsVuln, Fully_Qualified_Loc, Type, Message, File, Line, Matched,
			Rule, Rule_Number, Severity, Context
		]
		return ','.join(str(x) for x in sub)

	# endregion

	@staticmethod
	def output_structure() -> list:
		return [
			"Fully_Qualified_Name", "File_Name", "Number_of_Imports",
			"Time_Taken", "IsVuln", "Fully_Qualified_Loc", "Type", "Message",
			"File", "Line", "Matched", "Rule", "Rule_Number", "Severity",
			"Context"
		]

	def add_issue(self, struct: file_scan_struct):
		output = []
		base = ', '.join([
			self.escape_string(struct.qual_name),
			self.escape_string(struct.file),
			self.escape_string(struct._imports_num),
			self.escape_string(struct.run_time)
		])

		if hasattr(struct, 'vuln') and len(struct.vuln) > 0:
			for vuln in struct.vuln:
				output += [
					f"{base}, true, {self.transform_file_vuln(vuln)}"
				]
		else:
			output += [f"{base},false,,,,,,,,,,"]
		if output:
			self.append(output)

	def transform_file_vuln(self, self_vuln: vuln):
		return str(f"{self.escape_string(self_vuln.fully_qualified_loc)},"
				   f"{self.escape_string(self_vuln.type)},"
				   f"{self.escape_string(self_vuln.message)},"
				   f"{self.escape_string(self_vuln.file)},"
				   f"{self.escape_string(self_vuln.line)},"
				   f"{self.escape_string(self_vuln.matched)},"
				   f"{self.escape_string(self_vuln.rule)},"
				   f"{self.escape_string(self_vuln.rule_num)},"
				   f"{self.escape_string(self_vuln.severity)},"
				   f"{self.escape_string(self_vuln.context)}")

class sqlite(Structure):

	def escape_string(self, string: object):
		if isinstance(string, bool):
			return "'true'" if string else "'false'"
		elif isinstance(string, int):
			return string
		else:
			return "'" + str(string).replace("'", '"').replace('<', '').replace(
				'>', '').replace('/', '\/') + "'"

	def __init__(self,
				 path,
				 outputName: str = "TEMP_FILE",
				 all_files: bool = False):

		try:
			os.remove(self.output_file)
		except:
			pass

		self.already_exists = os.path.exists(outputName)
		self.connection = sqlite3.connect(outputName)
		self.cursor = self.connection.cursor()

		super().__init__(path=path,
						 output_type="sqlite",
						 output_name=outputName,
						 open_writer=False,
						 all_files=all_files)

	def writeHeader(self):
		if not self.already_exists:
			from src.cryptolation import NAME
			# yapf: disable
			try:
				self.cursor.execute(f"""
						CREATE TABLE {NAME}(
							FILE VARCHAR(255) NOT NULL,
							IMPORTS INT,
							TIMETAKEN VARCHAR(255),
							ISVULN BOOLEAN NOT NULL,
							FULLQUALLOC VARCHAR(255),
							TYPE VARCHAR(255),
							MESSAGE VARCHAR(255),
							LINE INT,
							MATCHED VARCHAR(255),
							RULE VARCHAR(255),
							RULENUMBER TINYINT(1),
							SEVERITY CHAR(20),
							CONTEXT VARCHAR(255)
						);""")
				self.connection.commit()
			except Exception as e:
				pass
		# yapf: enable
		return

	def writeFooter(self):
		try:
			self.connection.close()
		except Exception as e:
			pass
		return

	def add_issue(self, struct: file_scan_struct):
		from src.cryptolation import NAME
		if hasattr(struct, 'vuln') and len(struct.vuln) > 0:
			for vuln in struct.vuln:
				# yapf: disable
				try:
					self.cursor.execute(
					 f"""INSERT INTO {NAME} 
					(FILE,IMPORTS,TIMETAKEN,ISVULN,FULLQUALLOC,TYPE,MESSAGE,LINE,MATCHED,
					RULE,RULENUMBER,SEVERITY,CONTEXT) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);""",
					 (
					  self.escape_string(struct.file),
					  self.escape_string(struct.imports_num()),
					  self.escape_string(struct.run_time),
					  self.escape_string(True),
					  self.escape_string(vuln.fully_qualified_loc),
					  self.escape_string(vuln.type),
					  self.escape_string(vuln.message),
					  self.escape_string(vuln.line),
					  self.escape_string(vuln.matched),
					  self.escape_string(vuln.rule),
					  self.escape_string(vuln.rule_num),
					  self.escape_string(vuln.severity),
					  self.escape_string(vuln.context)))

					self.connection.commit()
				except Exception as e:
					pass
				# yapf: enable
		else:
			# yapf: disable
			try:
				self.cursor.execute(
				 f"""INSERT INTO {NAME} 
				(FILE,IMPORTS,TIMETAKEN,ISVULN) VALUES  (?,?,?,?);""",
				 (
				   self.escape_string(struct.file),
				   self.escape_string(struct.imports_num()),
				   self.escape_string(struct.run_time),
				   self.escape_string(False)))
				self.connection.commit()
			except Exception as e:
				pass
			# yapf: enable
		return

class sbom(Structure, BaseParser):

	def escape_string(self, string: object) -> str:
		return str(string)

	def __init__(self,
				 path,
				 outputName: str = "TEMP_FILE",
				 all_files: bool = False):
		try:
			os.remove(self.output_file)
		except:
			pass

		self._components = []
		super().__init__(path=path,
						 output_type="xml",
						 output_name=outputName,
						 open_writer=False,
						 all_files=all_files)

	def get_components(self):
		return self._components

	def writeHeader(self):
		return

	def writeFooter(self):
		try:
			bom = Bom.from_parser(self)
			formatter =  output.get_instance(
				bom,
				output_format=output.OutputFormat.XML
			)
			formatter.output_to_file(self.output_file, True)
		except Exception as e:
			pass
		return

	def add_issue(self, struct: file_scan_struct):
		sha1 = hashlib.sha1()
		sha512 = hashlib.sha512()

		with open(struct.file, 'rb') as f:
			while True:
				data = f.read(65536)
				if not data:
					break
				sha1.update(data)
				sha512.update(data)

		component = Component(
			name=struct.qual_name,
			version="undetermined"
		)

		component.add_hash(HashType.from_composite_str(f"sha1:{sha1.hexdigest()}"))
		component.add_hash(HashType.from_composite_str(f"sha512:{sha512.hexdigest()}"))

		if hasattr(struct, 'vuln') and len(struct.vuln) > 0:
			for vuln_itr, vuln in enumerate(struct.vuln):
				if vuln.severity == "H":
					severity = VulnerabilitySeverity.HIGH
				elif vuln.severity == "M":
					severity = VulnerabilitySeverity.MEDIUM
				else:# if vuln.severity == "L":
					severity = VulnerabilitySeverity.LOW

				component.add_vulnerability(
					Vulnerability(
						id=self.escape_string(vuln_itr),
						description=self.escape_string(vuln.message),
						source_name=self.escape_string(vuln.fully_qualified_loc),
						ratings=[VulnerabilityRating(severity=severity)],
					)
				)
		self._components.append(component)
		return