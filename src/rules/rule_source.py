import json
import os

# region Src
try:
	from src.utils import utils
	from src.utils.utils import get_fully_qualified_name, safe_get
except Exception as e:
	# print(e)
	pass
try:
	from utils import utils
	from utils.utils import get_fully_qualified_name, safe_get
except Exception as e:
	# print(e)
	pass
# endregion

common_regex = {
	'SHA':
		"sha | SHA\\(",  
	'ARC': "arc | ARC\\(",
	'AES': "aes | AES\\(",
	'MD': "md | MD *",
	'SAFE': "^((?!safe_).)",
	'LOAD': "load(s)?",
	'DES': "DES*",
	'URL': "^http://.*",
}

source = {
	"re": [{
		"group": 18,
		"criteria": "search",
		"arguments": [{
			"value": "re.escape*",
			"type": "string",
			"index": 0
		}]
	}],
	"pickle": [{
		"group": 17,
		"criteria":
			common_regex['LOAD']  # catches both load and loads
	}],
	"yaml": [{
		"group":
			16,
		"criteria":
			common_regex['SAFE'
						]  # Checking for methods that don't have safe prefix
	}],
	"ruamel.yaml": [{
		"group":
			16,
		"criteria":
			common_regex['SAFE'
						]  # Checking for methods that don't have safe prefix
	}],
	"xml.sax": [{
		"group": 15,
		"criteria": "*"
	}],
	"xml.etree": [{
		"group": 15,
		"criteria": "*"
	}],
	"xml.dom": [{
		"group": 15,
		"criteria": "*"
	}],
	"xmlrpc": [{
		"group": 15,
		"criteria": "*"
	}],
	"lxml": [{
		"group": 15,
		"criteria": "*"
	}],
	"genshi": [{
		"group": 15,
		"criteria": "*"
	}],
	"cryptography.hazmat.primitives.ciphers.algorithms": [{
		"group": 9,
		"criteria": common_regex['AES']
	}, {
		"group": 9,
		"criteria": common_regex['ARC']
	}, {
		"group": 11,
		"criteria": common_regex['SHA']
	}, {
		"group": 9,
		"criteria": "Blowfish"
	}, {
		"group": 9,
		"criteria": "IDEA"
	}, {
		"group": 9,
		"criteria": "TripleDES"
	}],
	"pyDes": [{
		"group": 9,
		"criteria": "des"
	}, {
		"group": 9,
		"criteria": "triple_des"
	}],
	"Crypto.Cipher": [{
		"group": 9,
		"criteria": "PKCS1_v1_5"
	}, {
		"group": 9,
		"criteria": "AES"
	}, {
		"group": 9,
		"criteria": "XOR"
	}, {
		"group": 9,
		"criteria": "Blowfish"
	}, {
		"group": 9,
		"criteria": common_regex['DES']
	}, {
		"group": 9,
		"criteria": "ARC*"
	}],
	"Cryptodome.Cipher": [{
		"group": 9,
		"criteria": common_regex['DES']
	}, {
		"group": 9,
		"criteria": common_regex['ARC']
	}, {
		"group": 9,
		"criteria": "XOR"
	}, {
		"group": 9,
		"criteria": "Blowfish"
	}, {
		"group": 9,
		"criteria": "AES"
	}, {
		"group": 9,
		"criteria": "PKCS1_v1_5"
	}, {
		"group": 9,
		"criteria": "PKCS1_OAEP"
	}],
	"Cryptodome.Hash": [{
		"group": 11,
		"criteria": common_regex['SHA']
	}, {
		"group": 11,
		"criteria": common_regex['MD']
	}],
	"Crypto.Hash": [{
		"group": 11,
		"criteria": common_regex['SHA']
	}, {
		"group": 11,
		"criteria": common_regex['MD']
	}],
	"cryptography.hazmat.primitives.hashes": [{
		"group": 11,
		"criteria": common_regex['SHA']
	}, {
		"group": 11,
		"criteria": common_regex['MD']
	}],
	"cryptography.hazmat.primitives.kdf.pbkdf2": [{
		"group": 6,
		"criteria": "PBKDF2HMAC",
		"arguments": [{
			"type": "secure",
			"name": "salt",
			"index": 2
		}]
	}],
	"crypt": [{
		"group": 6,
		"criteria": "crypt",
		"arguments": [{
			"type": "include_secure",
			"name": "salt",
			"index": 2
		}]
	}],
	"jwt": [{
		"group": 12,
		"criteria": "decode",
		"arguments": [{
			"value": False,
			"type": "bool",
			"name": "verify"
		}]
	}, {
		"group":
			12,
		"criteria":
			"decode",
		"arguments": [{
			"type": "json",
			"name": "options",
			"value": "{\"verify_signature\":false}"
		}]
	}, {
		"group": 12,
		"criteria": "decode",
		"arguments": [{
			"value": False,
			"type": "bool",
			"name": "verify"
		}]
	}, {
		"group":
			12,
		"criteria":
			"decode",
		"arguments": [{
			"type": "json",
			"name": "options",
			"value": "{\"verify_signature\":false}"
		}]
	}, {
		"group":
			12,
		"criteria":
			"process_jwt",
		"arguments": [{
			"type": "include_json",
			"name": "options",
			"value": "{\"verify_signature\":false}"
		}]
	}],
	"cryptography.hazmat.primitives.ciphers.modes": [{
		"group": 7,
		"criteria": "ECB"
	}],
	"cryptography.hazmat.primitives.serialization.pkcs12": [{
		"group": 1,
		"criteria": "serialize_key_and_certificates"
	}],
	"bcrypt": [{
		"group":
			6,
		"criteria":
			"kdf",
		"arguments": [{
			"value": 50,
			"type": "int",
			"name": "rounds",
			"index": 2
		}, {
			"value": 1000,
			"type": "len",
			"name": "salt",
			"index": 1
		}]
	}],
	"cryptography.hazmat.primitives.asymmetric.padding": [{
		"group": 10,
		"criteria": "PKCS1v15"
	}],
	"cryptography.hazmat.primitives.asymmetric": [{
		"group": 10,
		"criteria": "rsa"
	}, {
		"group": 10,
		"criteria": "ec"
	}, {
		"group": 10,
		"criteria": "dsa"
	}],
	"httplib": [{
		"group":
			4,
		"criteria":
			"HTTPSConnection",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"pycurl": [{
		"group":
			4,
		"criteria":
			"setopt",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"http": [{
		"group":
			4,
		"criteria":
			"client.HTTPSConnection",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"six": [{
		"group":
			4,
		"criteria":
			"moves.http_client.HTTPSConnection",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"six.moves.urllib.request": [{
		"group":
			4,
		"criteria":
			"urlopen",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"urlretrieve",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"URLopener",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"FancyURLopener",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"urllib": [{
		"group":
			4,
		"criteria":
			"urlopen",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"urlretrieve",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"URLopener",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"FancyURLopener",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"urllib.request.URLopener": [{
		"group":
			4,
		"criteria":
			"open",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "fullurl",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"open_unknown",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "fullurl",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"retrieve",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"urllib2": [{
		"group":
			4,
		"criteria":
			"urlopen",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"Request",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"urllib.request": [{
		"group":
			4,
		"criteria":
			"Request",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"builder":
			True,
		"group":
			4,
		"criteria":
			"urlopen",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"index": 0
		}]
	}, {
		"builder":
			True,
		"group":
			4,
		"criteria":
			"urlretrieve",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"index": 0
		}]
	}, {
		"builder":
			True,
		"group":
			4,
		"criteria":
			"URLopener",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"index": 0
		}]
	}, {
		"builder":
			True,
		"group":
			4,
		"criteria":
			"FancyURLopener",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"index": 0
		}]
	}],
	"requests": [{
		"group":
			4,
		"criteria":
			"*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group": 1,
		"criteria": "*",
		"arguments": [{
			"value": "False",
			"type": "bool",
			"name": "verify"
		}]
	}, {
		"group":
			2,
		"criteria":
			"CURL_CA_BUNDLE",
		"arguments": [{
			"value": "ssl._create_unverified_context",
			"type": "string"
		}]
	}, {
		"group": 2,
		"criteria": "*",
		"target": "CURL_CA_BUNDLE",
		"arguments": [{
			"value": "*",
			"type": "regex",
			"name": "CURL_CA_BUNDLE"
		}]
	}, {
		"group":
			2,
		"criteria":
			"models.Request",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"requests.api": [{
		"group":
			4,
		"criteria":
			"*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"requests.sessions.Session": [{
		"group":
			4,
		"criteria":
			"*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"webbrowser": [{
		"group":
			4,
		"criteria":
			"open",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"requests.Session": [{
		"group":
			4,
		"criteria":
			"*",
		"class_name":
			"requests.sessions.Session",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"hashlib": [{
		"group":
			8,
		"criteria":
			"pbkdf2_hmac",
		"arguments": [{
			"value": 1000,
			"type": "include_int",
			"index": 3
		}, {
			"type": "include_secure",
			"index": 2,
			"name": "salt"
		}]
	}, {
		"group": 11,
		"criteria": common_regex['SHA']
	}, {
		"group": 11,
		"criteria": common_regex['MD']
	}],
	"ssl": [{
		"group": 1,
		"criteria": "ssl.SSLContext.check_hostname",
		"target": "False"
	}, {
		"group": 1,
		"criteria": "*",
		"target": "ssl._create_unverified_context",
	}, {
		"group": 1,
		"criteria": "*",
		"target": "ssl._create_stdlib_context",
	}, {
		"group": 1,
		"criteria": "ssl.SSLContext.verify_mode",
		"target": "ssl.CERT_NONE"
	}, {
		"group":
			3,
		"criteria":
			"_create_default_https_context",
		"arguments": [{
			"value": "ssl._create_unverified_context",
			"type": "string"
		}]
	}, {
		"group": 3,
		"criteria": "_create_default_https_context",
		"arguments": [{
			"value": "ssl._create_stdlib_context",
			"type": "string"
		}]
	}, {
		"group": 13,
		"criteria": "SSLContext",
		"arguments": [{
			"type": "include_secure",
			"index": 0
		}]
	}, {
		"group":
			13,
		"criteria":
			"wrap_socket",
		"arguments": [{
			"type": "include_secure",
			"name": "ssl_version",
			"index": 0
		}]
	}],
	"md5": [{
		"group": 11,
		"criteria": "*"
	}],
	"OpenSSL.SSL": [{
		"group": 13,
		"criteria": "TLSv1_1_METHOD"
	}, {
		"group": 13,
		"criteria": "TLSv1_0_METHOD"
	}, {
		"group": 13,
		"criteria": "Context",
		"arguments": [{
			"type": "secure",
			"index": 0
		}]
	}, {
		"group":
			13,
		"criteria":
			"set_verify",
		"arguments": [{
			"value": "SSL.VERIFY_NONE",
			"type": "string",
			"index": 0
		}]
	}],
	"telnet": [{
		"group": 14,
		"criteria": "*"
	}],
	"random": [{
		"group": 5,
		"criteria": "*"
	}],
	"ftplib": [{
		"group": 14,
		"criteria": "*"
	}],
	"httproxy": [{
		"group": 4,
		"criteria": "*"
	}],
	"Crypto": [{
		"group": 11,
		"criteria": "*"
	}],
	"aiohttp.web_request.BaseRequest": [{
		"group":
			4,
		"criteria":
			"clone",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "rel_url"
		}]
	}],
	"tornado.web.RequestHandler": [{
		"group":
			4,
		"criteria":
			"redirect",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}],
	"pandas.io": [{
		"group":
			4,
		"criteria":
			"*.read_*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "path",
			"index": 0
		}]
	}],
	"furl.furl": [{
		"group":
			4,
		"criteria":
			"*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "path",
			"index": 0
		}]
	}],
	"PIL.Image": [{
		"group":
			4,
		"criteria":
			"open",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "fp",
			"index": 0
		}]
	}],
	"PIL.Image.Image": [{
		"group":
			4,
		"criteria":
			"save",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "fp",
			"index": 0
		}]
	}],
	"aiohttp.client.ClientSession": [{
		"group":
			4,
		"criteria":
			"*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"request",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 1
		}]
	}],
	"socket.socket": [{
		"group":
			4,
		"criteria":
			"connect",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "address",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"connect_ex",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "address",
			"index": 0
		}]
	}],
	"socket": [{
		"group":
			4,
		"criteria":
			"create_connection",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "address",
			"index": 0
		}]
	}],
	"http.client": [{
		"group": 4,
		"criteria": "HTTPConnection"
	}, {
		"group":
			4,
		"criteria":
			"HTTPSConnection",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "host",
			"index": 0
		}]
	}],
	"smtplib": [{
		"group":
			4,
		"criteria":
			"*",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "host",
			"index": 0
		}]
	}],
	"werkzeug": [{
		"group":
			4,
		"criteria":
			"redirect",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "location",
			"index": 0
		}]
	}],
	"requests.models.PreparedRequest": [{
		"group":
			4,
		"criteria":
			"prepare",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 1
		}]
	}, {
		"group":
			4,
		"criteria":
			"prepare_url",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 0
		}]
	}, {
		"group":
			4,
		"criteria":
			"prepare_auth",
		"arguments": [{
			"value": common_regex['URL'],
			"type": "regex",
			"name": "url",
			"index": 1
		}]
	}],
	"paramiko.client": [{
		"group":
			4,
		"criteria":
			"SSHClient.set_missing_host_key_policy",
		"arguments": [{
			"value": "paramiko.client.AutoAddPolicy",
			"type": "string",
			"index": 0
		}]
	}],
	"pyOpenSSL.SSL": [{
		"group": 13,
		"criteria": "Context",
		"arguments": [{
			"type": "include_secure",
			"name": "method",
			"index": 0
		}]
	}],
	"ldap": [{
		"group": 14,
		"criteria": "simple_bind",
		"class_name": "ldap.ldapobject.SimpleLDAPObject",
		"arguments": [{
			"value": "1",
			"type": "include_len",
			"index": 1
		}]
	}, {
		"group": 14,
		"criteria": "simple_bind_s",
		"class_name": "ldap.ldapobject.SimpleLDAPObject",
		"arguments": [{
			"value": "1",
			"type": "include_len",
			"index": 1
		}]
	}, {
		"group": 14,
		"criteria": "bind_s",
		"class_name": "ldap.ldapobject.SimpleLDAPObject",
		"arguments": [{
			"value": "1",
			"type": "include_len",
			"index": 1
		}]
	}, {
		"group": 14,
		"criteria": "bind",
		"class_name": "ldap.ldapobject.SimpleLDAPObject",
		"arguments": [{
			"value": "1",
			"type": "include_len",
			"index": 1
		}]
	}],
	"ucryptolib": [{
		"group":
			7,
		"criteria":
			"aes",
		"arguments": [{
			"value": "MODE_ECB",
			"type": "regex",
			"name": "mode",
			"index": 1
		}]
	}, {
		"group": 10,
		"criteria": "aes",
		"arguments": [{
			"type": "include_secure",
			"name": "IV",
			"index": 2
		}]
	}, {
		"group": 10,
		"criteria": "aes",
		"arguments": [{
			"type": "include_secure",
			"name": "key",
			"index": 0
		}]
	}],
	"nacl": [{
		"group": 0,
		"criteria": "secret.SecretBox",
		"arguments": [{
			"type": "include_secure",
			"name": "key",
			"index": 0
		}]
	}, {
		"group": 6,
		"criteria": "pwhash.argon2i.kdf",
		"arguments": [{
			"type": "include_secure",
			"name": "salt",
			"index": 2
		}]
	}],
	"M2Crypto.EVP": [{
		"group":
			0,
		"criteria":
			"pbkdf2",
		"arguments": [{
			"value": 1000,
			"type": "include_secure",
			"name": "key",
			"index": 0
		}, {
			"value": 1000,
			"type": "include_len",
			"name": "iter",
			"index": 2
		}, {
			"type": "include_secure",
			"name": "salt",
			"index": 1
		}]
	}, {
		"group":
			0,
		"criteria":
			"Cipher",
		"arguments": [{
			"type": "include_secure",
			"name": "key",
			"index": 1
		}, {
			"type": "include_secure",
			"name": "iv",
			"index": 2
		}, {
			"value": "ecb",
			"type": "regex",
			"name": "alg",
			"index": 0
		}]
	}]
}

rule_groups = {
	0: {
		'name': 'Predictable/Constant Cryptographic keys',
		'Message': 'Used a Predictable and Constant Cryptographic Key',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Predictable Secrets",
		"Analysis Method": ""
	},
	1: {
		'name': 'Use Wildcard Verifiers to Accept All Hosts',
		'Message': 'Use a wildcard to Avoid Verification',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	2: {
		'name':
			'Create Custom String to Trust All Certificates',
		'Message':
			'Created a Custom String to avoid verification of Certificates',
		'CWE':
			'',
		'Severity':
			"H",
		"Crypto Property":
			"C/I/A",
		"Attack Type":
			"SSL/TLS MitM",
		"Analysis Method":
			""
	},
	3: {
		'name': 'Create Unverified HTTPS Context',
		'Message': 'Use a unverified context to avoid HTTPS Verification',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	4: {
		'name': 'Use of HTTP',
		'Message': 'Using http instead of https',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	5: {
		'name': 'Cryptographically Insecure PRNGs',
		'Message': 'Using Insecure Random Number Generation',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Randomness",
		"Attack Type": "Predictability",
		"Analysis Method": ""
	},
	6: {
		'name': 'Static Salts',
		'Message': 'Using a static and insecure Salt',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	7: {
		'name': 'ECB Mode In Symmetric Ciphers',
		'Message': 'Using an Insecure Mode',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	8: {
		'name': 'Fewer Than 1000 Iterations',
		'Message': 'Using less than 1000 Iterations',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	9: {
		'name': 'Using Insecure Block Ciphers',
		'Message': 'Using an Insecure Block Cipher',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	10: {
		'name': 'Insecure Asymmetric Ciphers',
		'Message': 'Using an Insecure Asymmetric Cipher',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "C/A",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	11: {
		'name': 'Insecure Cryptographic Hash',
		'Message': 'Using an insecure Hash',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Integrity",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	12: {
		'name': 'Not Verifying a Json Web Token',
		'Message': 'Not verifying the Json Web Token (JWT)',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	13: {
		'name': 'Using an insecure TLS Version',
		'Message': 'Using a deprecated or invalid TLS Version',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Confidentiality",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	14: {
		'name': 'Using an Insecure Protocol',
		'Message': 'Using an insecure protocol',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	15: {
		'__link__':
			'https://docs.python.org/3/library/xml.html#xml-vulnerabilities',
		'name':
			'Using an Insecure XML Deserialization',
		'Message':
			'Using an insecure XML Deserialization',
		'CWE':
			'',
		'Severity':
			"M",
		"Crypto Property":
			"Integrity",
		"Attack Type":
			"Deserialization",
		"Analysis Method":
			""
	},
	16: {
		'__link__': 'LINK',
		'name': 'Using an Insecure YAML Deserialization',
		'Message': 'Using an insecure YAML Deserialization',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Integrity",
		"Attack Type": "Deserialization",
		"Analysis Method": ""
	},
	17: {
		'__link__':
			'https://docs.python.org/3/library/pickle.html#restricting-globals',
		'name':
			'Using an Insecure Pickle Deserialization',
		'Message':
			'Using an insecure Pickle Deserialization',
		'CWE':
			'',
		'Severity':
			"H",
		"Crypto Property":
			"Integrity",
		"Attack Type":
			"Deserialization",
		"Analysis Method":
			""
	},
	18: {
		'__link__':
			'https://rules.sonarsource.com/python/type/Vulnerability/RSPEC-2631',
		'name':
			'Not escaping the regex expression',
		'Message':
			'Not escaping the regex expression',
		'CWE':
			'',
		'Severity':
			"M",
		"Crypto Property":
			"Integrity",
		"Attack Type":
			"Brute-Force",
		"Analysis Method":
			""
	},
	-1: {
		'name': 'UNKNOWN',
		'Message': 'UNKNOWN',
		'CWE': 'UNKNOWN',
		'Severity': "UNKNOWN",
		"Crypto Property": "UNKNOWN",
		"Attack Type": "UNKNOWN",
		"Analysis Method": "UNKNOWN"
	},
}

secure_values = [{
	'name': 'python3_randcryptomNumberGenerator',
	'imports': 'os',
	'criteria': 'urandom',
	'builder': False,
	'group': 5
}, {
	'name': 'python3_SSL_ONE',
	'imports': 'SSL',
	'criteria': 'TLSv1_2_METHOD',
	'builder': False,
	'group': 5
}, {
	'name': 'python3_ssl_one',
	'imports': 'ssl',
	'criteria': 'PROTOCOL_TLSv1_2',
	'builder': False,
	'group': 5
}]

default_imports = {
	'Crypto.Cipher': [
		'AES', 'ARC2', 'ARC4', 'Blowfish', 'CAST', 'DES', 'DES3', 'XOR',
		'PKCS1_v1_5', 'PKCS1_OAEP'
	],
	'hashlib': [
		'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'blake2b',
		'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128',
		'shake_256', 'pbkdf2_hmac'
	],
}


def unwravel(obj, search_dyct: dict = rule_groups):
	try:
		if isinstance(int, dict):
			item = search_dyct.get(obj['group'])
		else:
			item = search_dyct.get(obj)

		return item['name'], item['Message'], item['Severity']
	except Exception as e:
		return None, None


def load(extra_rules: str = None) -> (dict, dict):
	"""
		Returns the internal set of json rules along with any extra rules specified
r
		@param extra_rules: toDict
		@return: toDict
		"""
	global source
	global secure_values

	if extra_rules:
		with open(extra_rules, 'r') as reader:
			source = {**source, **json.load(reader)}

	return source, secure_values


def rule_check(rule: dict, value: str, secure_values: dict) -> str:
	"""
		Checking if the given value is validated* against the rule it triggered.
		* in this context validated means matches an insecure value

		@param rule: toDict
		@param value: str
		@param secure_values: toDict
		@return: str
		"""
	value = str(value)
	if rule['live_type'] == "int":
		if int(value) < rule['value']:
			return f"Value {value} is less than the required value of {rule['value']}"
	elif rule['live_type'] == "string":
		if utils.compare(value, rule['value']):
			return f"Value {value} cannot be set to {rule['value']}"
	elif rule['live_type'] == "bool":
		if value == str(rule['value']):
			return f"Value {value} should not be set to {rule['value']}"
	elif rule['live_type'] == "len":
		if len(value) < rule['value']:
			return f"Value {value} is less than the required value of {rule['value']}"
	elif rule['live_type'] == 'regex':
		if rule['value'] == "*":
			return 'This variable should not have an assignment'
		import re
		if re.match(rule['value'], value):
			return f"Value {value} should not be used, breaks the regex: {rule['value']}"
	elif rule['live_type'] == 'secure':
		# region Src
		try:
			from src.utils.utils import get_fully_qualified_name, compare
		except Exception as e:
			pass
		try:
			from utils.utils import get_fully_qualified_name, compare
		except Exception as e:
			pass
		# endregion
		if not any(
				list(
					map(
						lambda sec: compare(
							f"{get_fully_qualified_name(sec)}.{sec['criteria']}",
							value,
							strip_start=True), secure_values))):
			return f"Value {value} is not secure"
	elif rule['live_type'] == 'json':
		import json
		json_value, rule_values = json.loads(value), json.loads(rule['value'])

		for union_value in list(rule_values.keys() & json_value.keys()):
			if rule_values[union_value] == json_value[union_value]:
				return f"Value {union_value} should not be set to {json_value[union_value]}"
	elif rule['live_type'] == 'tuple':
		import json
		json_value, rule_values = json.loads(value), json.loads(rule['value'])

		for union_value in list(rule_values.keys() & json_value.keys()):
			if rule_values[union_value] == json_value[union_value]:
				return f"Value {union_value} should not be set to {json_value[union_value]}"
		return False
	return None
