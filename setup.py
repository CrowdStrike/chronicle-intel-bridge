from setuptools import find_packages
from setuptools import setup
from glob import glob
from os.path import basename
from os.path import splitext
import ccib

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="ccib",
    version=ccib.__version__,
    author="CrowdStrike Solution Architects",
    author_email="integrations@crowdstrike.com",
    description="The CrowdStrike to Chronicle Intel Bridge",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/crowdstrike/chronicle-intel-bridge",
    packages=find_packages("ccib"),
    package_dir={"": "ccib"},
    py_modules=[splitext(basename(path))[0] for path in glob("ccib/*.py")],
    include_package_data=True,
    install_requires=[
        'crowdstrike-falconpy',
        'google-api-python-client'
    ],
    extras_require={
        'devel': [
            'flake8',
            'pylint',
            'pytest',
            'bandit',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.11',
)
