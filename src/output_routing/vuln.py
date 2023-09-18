class Klass:

	def __init__(self,
				 type: str = None,
				 message: str = None,
				 file: str = None,
				 line: int = None,
				 matched: str = None,
				 rule: str = None,
				 rule_num: int = None,
				 severity: str = None,
				 context: list = None,
				 kol: int = None):
		self.type = type
		self.message = message
		self.file = file
		self.line = int(line)
		self.matched = matched
		self.rule = rule
		self.rule_num = int(rule_num)
		self.severity = severity
		self.context = context
		self.fully_qualified_loc = None
		self.kol = int(kol) if kol is not None else None

	def __baseDict(self):
		return {
			'Qualified Loc': self.fully_qualified_loc,
			'File': self.file,
			'Line': self.line,
			'Kol': self.kol,
			'Rule Number': self.rule_num,
			'Severity': self.severity,
			'Context': self.context
		}

	def toDict(self):
		return {
			'Qualified Loc': self.fully_qualified_loc,
			'Type': self.type,
			'Message': self.message,
			'File': self.file,
			'Line': self.line,
			'Kol': self.kol,
			'Matched': self.matched,
			'Rule': self.rule,
			'Rule Number': self.rule_num,
			'Severity': self.severity,
			'Context': self.context
		}

	def is_(self, item):
		return isinstance(item, Klass) and all(
			self[attribute] == item[attribute]
			for attribute in list(self.toDict().keys()))

	def is_of(self, item):
		baseCheck = isinstance(item, Klass) and all(
			self[attribute] == item[attribute]
			for attribute in list(self.__baseDict().keys()))

		if not baseCheck:
			return False
		import re
		return re.match(self.type, item.type) or re.match(item.type, self.type)

	def __getitem__(self, item):
		return self.toDict()[item]

	def __str__(self):
		return str(self.toDict())

	def __repr__(self):
		return str(self.toDict())

	@property
	def base_str(self):
		output = self.toDict()
		output['Context'] = None
		return output
