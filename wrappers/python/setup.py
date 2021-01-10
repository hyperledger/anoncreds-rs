"""Module setup."""

import os
import runpy
from setuptools import find_packages, setup

PACKAGE_NAME = "indy_credx"
version_meta = runpy.run_path("./{}/version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]

with open(os.path.abspath("./README.md"), "r") as fh:
    long_description = fh.read()

if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        author="Hyperledger Indy Contributors",
        author_email="indy@lists.hyperledger.org",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/hyperledger/indy-shared-rs",
        packages=find_packages(),
        include_package_data=True,
        package_data={
            "": [
                "indy_credx.dll",
                "libindy_credx.dylib",
                "libindy_credx.so",
            ]
        },
        python_requires=">=3.6.3",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
            "Operating System :: OS Independent",
        ],
    )
