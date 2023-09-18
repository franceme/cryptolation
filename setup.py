#!/usr/bin/env python3
# region Imports
import pathlib, zipfile
from fileinput import FileInput as finput
import os
import sys
from setuptools import find_packages, setup
from pathlib import Path
import glob
from glob import glob as re
try:
	from pylint.reporters.json_reporter import JSONReporter
except:
	pass

#region Tests
try:
	from tests.test_suites import common_test, timeout, time_out
	from tests.tests import test_Synthasized_Tests
except:
	pass
try:
	from test_suites import common_test, timeout, time_out
	from tests import test_Synthasized_Tests
except:
	pass
#endregion
#region Src
try:
	from src import cryptolation
except:
	pass
try:
	import cryptolation
except:
	pass
try:
	from src.information import VERSION
except:
	pass
try:
	from information import VERSION
except:
	pass
#endregion

# endregion
# region Basic Information
here = os.path.abspath(os.path.dirname(__file__))
py_version = sys.version_info[:2]
NAME = "cryptolation"
AUTHOR = 'Miles Frantz'
EMAIL = 'frantzme@vt.edu'
DESCRIPTION = 'My short description for my project.'
GH_NAME = "franceme"
URL = f"https://github.com/{GH_NAME}/{NAME}"
long_description = pathlib.Path(f"{here}/README.md").read_text(encoding='utf-8')
REQUIRES_PYTHON = '>=3.8.0'
RELEASE = "?"
entry_point = f"src.{NAME}"


# endregion
# region CMD Line Usage
def selfArg(string):
	return __name__ == "__main__" and len(
		sys.argv) > 1 and sys.argv[0].endswith('/setup.py') and str(
			sys.argv[1]).upper() == str(string).upper()


if selfArg('upsmall'):
	update = (0, 0, 1)
elif selfArg('upmedium'):
	update = (0, 1, 0)
elif selfArg('uplarge'):
	update = (1, 0, 0)
else:
	update = None

if update:
	current_version = VERSION
	version_tuple = tuple(current_version.split('.'))
	updated_version_tuple = '.'.join(
		tuple(map(lambda i, j: str(int(i) + int(j)), update, version_tuple)))

	print(f"Updating to version: {updated_version_tuple}")
	for foil_path in ["src/information", "information"]:
		foil = foil_path + "/__init__.py"
		try:
			with finput(foil, inplace=True) as foil:
				for line in foil:
					if line.startswith("VERSION"):
						print(f"VERSION = \"{updated_version_tuple}\"")
		except:
			pass

	with finput('README.md', inplace=True) as foil:
		for line in foil:
			if line.startswith('## Current Version: '):
				print(f"## Current Version: {updated_version_tuple}")
			else:
				print(line, end='')
	sys.exit(0)
elif selfArg('test'):
	if len(sys.argv) >= 3:
		check = lambda value: value.endswith(f"_{sys.argv[2]}")
	else:
		check = lambda value: True

	for test in [
			method for method in dir(test_Synthasized_Tests.MyTestCase())
			if method.startswith('test_') and check
	]:
		getattr(test_Synthasized_Tests.MyTestCase(), test)()
	sys.exit(0)
elif selfArg('rules'):
	# region Rules Source
	try:
		from src.rules import rule_source as src_of_rules
	except:
		pass
	try:
		from rules import rule_source as src_of_rules
	except:
		pass
	# endregion
	rule_file = "current_rules.csv"
	if os.path.exists(rule_file):
		os.remove(rule_file)

	with open(rule_file, "w+") as writer:
		writer.write(', '.join([
			"Number",
			"Vulnerability",
			"Attack Type",
			"Crypto Property",
			"Severity",
			"Analysis Method",
		]) + "\n")
		for key, rule in src_of_rules.rule_groups.items():
			if int(key) > 0:
				writer.write(', '.join([
					str(key),
					str(rule['Message']),
					str(rule['Attack Type']),
					str(rule['Crypto Property']),
					str(rule['Severity']),
					str(rule['Analysis Method']),
				]) + "\n")
	sys.exit(0)
elif selfArg('libraries') or selfArg('targets'):
	# region Rules Source
	try:
		from src.rules import rule_source as src_of_rules
	except:
		pass
	try:
		from rules import rule_source as src_of_rules
	except:
		pass
	# endregion
	rule_file = "current_libraries.csv"
	if os.path.exists(rule_file):
		os.remove(rule_file)

	with open(rule_file, "w+") as writer:
		writer.write(', '.join([
			"Number",
			"Name",
			"# Patterns",
		]) + "\n")
		for itr, (key, rule) in enumerate(src_of_rules.source.items()):
			writer.write(', '.join([
				str(itr),
				str(key),
				str(len(rule)),
			]) + "\n")
	sys.exit(0)
elif selfArg('todo'):
	print(f"""
		""")
	sys.exit(0)
elif selfArg('techDebt'):
	"""
		#ifdef TECHDEBT
		comment example
		#endif
		"""
	for file in Path("src").rglob("*.py"):
		os.system(f"cpp -P {file} {file}")
	sys.exit(0)
elif selfArg('format'):

	def Run(string):
		print(string)
		try:
			os.system(string)
		except:
			pass

	#region Imports
	try:
		from yapf.yapflib.yapf_api import FormatFile
	except:
		Run(f"{sys.executable} -m pip install yapf")
		from yapf.yapflib.yapf_api import FormatFile
		pass
	try:
		import reindent
	except:
		Run(f"{sys.executable} -m pip install reindent")
		import reindent
		pass
	#endregion
	for folderpath in ["src", "tests", "TestingResources"]:
		#region Python Files
		python_files = [
			str(Path(filename).resolve())
			for filename in glob.iglob(os.path.join(folderpath, '**/*.py'),
									   recursive=True)
		]
		print(f"Formatting the folder {folderpath}")
		for file in python_files:
			try:
				FormatFile(str(file), style_config="google", in_place=True)
			except Exception as e:
				print(f"Failure with the file {file}: {e}")
			print(".", end='')
		print('')
		Run(f"reindent -n --newline LF {folderpath}/")
		print()
		for file in python_files:
			try:
				for line in finput(file, inplace=1):
					print(line.replace("	", "\t"), end='')
			except:
				pass
			print(".", end='')
		print('')
		#endregion
		#region Json Files
		import json

		for json_file in [
				str(Path(filename).resolve()) for filename in glob.iglob(
					os.path.join(folderpath, '**/*.json'), recursive=True)
		]:
			with open(json_file, "r") as reader:
				contents = json.load(reader)

			try:
				os.remove(json_file)
			except:
				pass

			with open(json_file, "w+", encoding="utf-8") as writer:
				json.dump(contents, writer, indent=4)

			from fileinput import FileInput as finput
			print(f"Changing spaces to tabs in file: {json_file}")
			for line in finput(json_file, inplace=1):
				print(line.replace("	", "\t"), end='')
		print()
		#endregion
	sys.exit(0)
elif selfArg('appImage') or selfArg('package') or selfArg('packer'):
	print("Creating the appimage")
	import platform, uuid
	current_os = platform.system()

	instructions = [
		f"pyinstaller", f"-n {NAME}.sh", f"--clean", f"--onefile", f"-y",
		f"--key={uuid.uuid4()}_{uuid.uuid4()}_{uuid.uuid4()}"
	]

	#if current_os != 'Linux':
	#   instructions += ["--console"]

	instructions += [f"{os.path.join(*entry_point.split('.'))}.py"]

	[os.system(x) for x in [f"rm -r dist/"]]
	print(f"Installers done")
	os.system(' '.join(instructions))
	print(f"Creation Done")
	sys.exit(0)
elif selfArg('run'):
	sys.exit(cryptolation.main(sys.argv[2:]))
elif selfArg('langFeatures'):
	import os, sys, mitosheet
	import pandas as pd
	from pathlib import Path
	naem = "LanguageFeatures"
	container = None
	for itr, f in enumerate(Path("tests/").rglob("*.py.csv")):
		if itr > 0:
			container = container.append(pd.read_csv(f), ignore_index=True)
		else:
			container = pd.read_csv(f)

	def checkForDirBase(obj):
		if len(str(obj).split('/')) >= 2:
			output = str(obj).split('/')[1]
			if output.endswith('.py'):
				return None
			else:
				return output
		return None

	container['Path'] = container.filepath.apply(lambda x: checkForDirBase(x))
	# container.to_csv(naem+".csv",encoding="utf-8")
	container.to_excel(naem + ".xlsx")

elif selfArg('install'):
	sys.exit(os.system('python3 -m pip install -e .'))
elif selfArg('genGit'):
	with open('LICENSE', 'w+') as writer:
		writer.write(f"""
																 Apache License
												   Version 2.0, January 2004
												http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

		  "License" shall mean the terms and conditions for use, reproduction,
		  and distribution as defined by Sections 1 through 9 of this document.

		  "Licensor" shall mean the copyright owner or entity authorized by
		  the copyright owner that is granting the License.

		  "Legal Entity" shall mean the union of the acting entity and all
		  other entities that control, are controlled by, or are under common
		  control with that entity. For the purposes of this definition,
		  "control" means (i) the power, direct or indirect, to cause the
		  direction or management of such entity, whether by contract or
		  otherwise, or (ii) ownership of fifty percent (50%) or more of the
		  outstanding shares, or (iii) beneficial ownership of such entity.

		  "You" (or "Your") shall mean an individual or Legal Entity
		  exercising permissions granted by this License.

		  "Source" form shall mean the preferred form for making modifications,
		  including but not limited to software source code, documentation
		  source, and configuration files.

		  "Object" form shall mean any form resulting from mechanical
		  transformation or translation of a Source form, including but
		  not limited to compiled object code, generated documentation,
		  and conversions to other media types.

		  "Work" shall mean the work of authorship, whether in Source or
		  Object form, made available under the License, as indicated by a
		  copyright notice that is included in or attached to the work
		  (an example is provided in the Appendix below).

		  "Derivative Works" shall mean any work, whether in Source or Object
		  form, that is based on (or derived from) the Work and for which the
		  editorial revisions, annotations, elaborations, or other modifications
		  represent, as a whole, an original work of authorship. For the purposes
		  of this License, Derivative Works shall not include works that remain
		  separable from, or merely link (or bind by name) to the interfaces of,
		  the Work and Derivative Works thereof.

		  "Contribution" shall mean any work of authorship, including
		  the original version of the Work and any modifications or additions
		  to that Work or Derivative Works thereof, that is intentionally
		  submitted to Licensor for inclusion in the Work by the copyright owner
		  or by an individual or Legal Entity authorized to submit on behalf of
		  the copyright owner. For the purposes of this definition, "submitted"
		  means any form of electronic, verbal, or written communication sent
		  to the Licensor or its representatives, including but not limited to
		  communication on electronic mailing lists, source code control systems,
		  and issue tracking systems that are managed by, or on behalf of, the
		  Licensor for the purpose of discussing and improving the Work, but
		  excluding communication that is conspicuously marked or otherwise
		  designated in writing by the copyright owner as "Not a Contribution."

		  "Contributor" shall mean Licensor and any individual or Legal Entity
		  on behalf of whom a Contribution has been received by Licensor and
		  subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
		  this License, each Contributor hereby grants to You a perpetual,
		  worldwide, non-exclusive, no-charge, royalty-free, irrevocable
		  copyright license to reproduce, prepare Derivative Works of,
		  publicly display, publicly perform, sublicense, and distribute the
		  Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
		  this License, each Contributor hereby grants to You a perpetual,
		  worldwide, non-exclusive, no-charge, royalty-free, irrevocable
		  (except as stated in this section) patent license to make, have made,
		  use, offer to sell, sell, import, and otherwise transfer the Work,
		  where such license applies only to those patent claims licensable
		  by such Contributor that are necessarily infringed by their
		  Contribution(s) alone or by combination of their Contribution(s)
		  with the Work to which such Contribution(s) was submitted. If You
		  institute patent litigation against any entity (including a
		  cross-claim or counterclaim in a lawsuit) alleging that the Work
		  or a Contribution incorporated within the Work constitutes direct
		  or contributory patent infringement, then any patent licenses
		  granted to You under this License for that Work shall terminate
		  as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
		  Work or Derivative Works thereof in any medium, with or without
		  modifications, and in Source or Object form, provided that You
		  meet the following conditions:

		  (a) You must give any other recipients of the Work or
				  Derivative Works a copy of this License; and

		  (b) You must cause any modified files to carry prominent notices
				  stating that You changed the files; and

		  (c) You must retain, in the Source form of any Derivative Works
				  that You distribute, all copyright, patent, trademark, and
				  attribution notices from the Source form of the Work,
				  excluding those notices that do not pertain to any part of
				  the Derivative Works; and

		  (d) If the Work includes a "NOTICE" text file as part of its
				  distribution, then any Derivative Works that You distribute must
				  include a readable copy of the attribution notices contained
				  within such NOTICE file, excluding those notices that do not
				  pertain to any part of the Derivative Works, in at least one
				  of the following places: within a NOTICE text file distributed
				  as part of the Derivative Works; within the Source form or
				  documentation, if provided along with the Derivative Works; or,
				  within a display generated by the Derivative Works, if and
				  wherever such third-party notices normally appear. The contents
				  of the NOTICE file are for informational purposes only and
				  do not modify the License. You may add Your own attribution
				  notices within Derivative Works that You distribute, alongside
				  or as an addendum to the NOTICE text from the Work, provided
				  that such additional attribution notices cannot be construed
				  as modifying the License.

		  You may add Your own copyright statement to Your modifications and
		  may provide additional or different license terms and conditions
		  for use, reproduction, or distribution of Your modifications, or
		  for any such Derivative Works as a whole, provided Your use,
		  reproduction, and distribution of the Work otherwise complies with
		  the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
		  any Contribution intentionally submitted for inclusion in the Work
		  by You to the Licensor shall be under the terms and conditions of
		  this License, without any additional terms or conditions.
		  Notwithstanding the above, nothing herein shall supersede or modify
		  the terms of any separate license agreement you may have executed
		  with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
		  names, trademarks, service marks, or product names of the Licensor,
		  except as required for reasonable and customary use in describing the
		  origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
		  agreed to in writing, Licensor provides the Work (and each
		  Contributor provides its Contributions) on an "AS IS" BASIS,
		  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
		  implied, including, without limitation, any warranties or conditions
		  of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
		  PARTICULAR PURPOSE. You are solely responsible for determining the
		  appropriateness of using or redistributing the Work and assume any
		  risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
		  whether in tort (including negligence), contract, or otherwise,
		  unless required by applicable law (such as deliberate and grossly
		  negligent acts) or agreed to in writing, shall any Contributor be
		  liable to You for damages, including any direct, indirect, special,
		  incidental, or consequential damages of any character arising as a
		  result of this License or out of the use or inability to use the
		  Work (including but not limited to damages for loss of goodwill,
		  work stoppage, computer failure or malfunction, or any and all
		  other commercial damages or losses), even if such Contributor
		  has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
		  the Work or Derivative Works thereof, You may choose to offer,
		  and charge a fee for, acceptance of support, warranty, indemnity,
		  or other liability obligations and/or rights consistent with this
		  License. However, in accepting such obligations, You may act only
		  on Your own behalf and on Your sole responsibility, not on behalf
		  of any other Contributor, and only if You agree to indemnify,
		  defend, and hold each Contributor harmless for any liability
		  incurred by, or claims asserted against, such Contributor by reason
		  of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

		  To apply the Apache License to your work, attach the following
		  boilerplate notice, with the fields enclosed by brackets "[]"
		  replaced with your own identifying information. (Don't include
		  the brackets!)  The text should be enclosed in the appropriate
		  comment syntax for the file format. We also recommend that a
		  file or class name and description of purpose be included on the
		  same "printed page" as the copyright notice for easier
		  identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

""")
	try:
		os.remove("README.md")
	except:
		pass
	with open('README.md', "w+") as writer:
		writer.write(f"""# {NAME} by {AUTHOR}

## Current Version: {VERSION}

""")
	sys.exit(0)
elif selfArg('clean') or selfArg('clear'):
	for ext in ['*.csv', '*.xlsx', '*.spec', '*.zip', '*.ipynb']:
		os.system(f"find tests -type f -name '{ext}' -exec rm {{}} \;")

	for ext in ['*.spec']:
		os.system(f"find . -type f -name '{ext}' -exec rm {{}} \;")
	sys.exit(0)
elif selfArg('zip'):
	outputName = 'Cryptolation.zip'

	if os.path.exists(outputName):
		os.system(f"rm {outputName}")

	zipf = zipfile.ZipFile(outputName, 'w', zipfile.ZIP_DEFLATED)
	success = 0
	try:
		zipf.write("setup.py")
		zipf.write("README.md")
		for root, dirs, files in os.walk('src/'):
			for file in [x for x in files if not x.endswith('.pyc')]:
				zipf.write(
					os.path.join(root, file),
					os.path.relpath(os.path.join(root, file),
									os.path.join('src/', '..')))
		print(f"Successful: {outputName}")
	except Exception as e:
		print(f"Failing the exception check: {e}")
		success = 1
		pass
	zipf.close()
	sys.exit(success)
elif selfArg('base'):
	base_file, base_output = "setup.py", "setup.csv"

	first = f"docker run  --rm -it  -v \"{os.path.abspath(os.curdir)}:/sync\" python:3.8.12-slim-buster"
	python_script = ';'.join(f"""import os
import sys
os.chdir("/sync")
os.system("python3 -m pip install astroid==2.4.2 setuptools==51.1.2 password_strength==0.0.3.post2")
from src import cryptoguard4py as scan
scan.main(["-s {base_file}", "-o {base_output}", "-a"])""".split('\n'))
	for arg in [f"{first} python -c '{python_script}'"]:
		print(arg)
		os.system(arg)
	success = 0 if os.path.exists(base_output) else 1
	print("Success" if success == 0 else "Failure")
	if success == 0:
		os.remove(base_output)
	sys.exit(success)
elif selfArg('up'):
	for cmd in [
			f"./setup.py zip && cp Cryptolation.zip TestingResources/Cryptolation.zip&& mv Cryptolation.zip TestingResources/TestingRealProjects/Cryptolation.zip",
			f"cd TestingResources && ./make.py archive && ./make.py remote"
	]:
		print(cmd)
		os.system(cmd)
	sys.exit(0)
elif selfArg('dockerfile'):
	if os.path.exists("Dockerfile"):
		os.remove("Dockerfile")

	with open("Dockerfile", "w+") as writer:
		writer.write(f"""FROM python:3.8
COPY . /app
WORKDIR /app
RUN pip install astroid==2.4.2 setuptools==50.3.2 password_strength==0.0.3.post2 cyclonedx-python-lib>=0.11.1
CMD ["python", "src/cryptoguard4py.py"]
""")
	sys.exit(0)
elif selfArg('zipy'):
	print(f"Creating a single file exe")
	try:
		os.system(f"rm {NAME}.zipy")
	except:
		pass
	for cmd in [
			f"python3 -m zipapp src/ -p \"/usr/bin/python3\" -m \"{NAME}:hollow_main\"  -o {NAME}.zipy"
	]:
		print(cmd)
		os.system(cmd)
	if os.path.exists(f"{NAME}.zipy"):
		print(f"The zipy file {NAME}.zipy has been created")
		sys.exit(0)
	else:
		print(f"There was a problem creating the zipy file")
		sys.exit(1)
# endregion
# region Setup

setup(
	name=NAME,
	version=VERSION,
	description=DESCRIPTION,
	long_description=long_description,
	long_description_content_type='text/markdown',
	author=AUTHOR,
	author_email=EMAIL,
	#cmdclass={'build_sphinx':BuildDoc},
	command_options={
		'build_sphinx': {
			'project': ('setup.py', NAME),
			'version': ('setup.py', VERSION),
			'release': ('setup.py', RELEASE),
			'source_dir': ('setup.py', 'source')
		}
	},
	python_requires=REQUIRES_PYTHON,
	url=URL,
	packages=find_packages(
		exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
	entry_points={
		'console_scripts': ['mycli=src.cryptoguard4py:main'],
	},
	install_requires=[
		"astroid==2.4.2",
		"setuptools==50.3.2",
		"password_strength==0.0.3.post2",
		"cyclonedx-python-lib>=0.11.1",
	],
	extras_require={
		'Deployment': ['pyinstaller==4.2'],
		'Documentation': [
			"alabaster==0.7.12",
			"Babel==2.9.0",
			"certifi==2020.12.5",
			"chardet==4.0.0",
			"colorama==0.4.4",
			"commonmark==0.9.1",
			"docutils==0.16",
			"idna==2.10",
			"imagesize==1.2.0",
			"Jinja2==2.11.2",
			"MarkupSafe==1.1.1",
			"mccabe==0.6.1",
			"packaging==20.8",
			"Pygments==2.7.4",
			"pyparsing==2.4.7",
			"pytz==2020.5",
			"recommonmark==0.7.1",
			"requests==2.25.1",
			"snowballstemmer==2.0.0",
			"timeout-decorator==0.5.0",
			"toml==0.10.2",
			"urllib3==1.26.2",
			"yapf==0.30.0",
		]
	},
	include_package_data=True,
	# license='MIT',
	classifiers=[
		# Trove classifiers
		# Full list: https:
		# 'License :: OSI Approved :: MIT License',
		'Programming Language :: Python',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.8',
	],
	test_suite='tests.test_suites',
	# $ setup.py publish support.
	#
	# cmdclass={
	#   'upload': UploadCommand,
	# },
)
# endregion
