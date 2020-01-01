from setuptools import setup, find_packages
import re

VERSIONFILE="minidump/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="minidump",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="skelsecprojects@gmail.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/minidump",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Python library to parse Windows minidump file format",
	long_description="Python library to parse Windows minidump file format",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	entry_points={
		'console_scripts': [
			'minidump = minidump.__main__:run',
		],
	}
)
