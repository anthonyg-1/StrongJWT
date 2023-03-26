from setuptools import setup, find_packages

VERSION = '0.0.1'
DESCRIPTION = 'Python library to validate JWTs.'
LONG_DESCRIPTION = 'Python library to validate JWTs to avoid common security issues.'

setup(
    name="StrongJWT",
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author="Tony Guimelli",
    author_email="tony.guimelli@gmail.com",
    license='MIT',
    packages=find_packages(),
    install_requires=["pyjwt", "requests"],
    keywords='conversion',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        'License :: OSI Approved :: MIT License',
        "Programming Language :: Python :: 3",
    ]
)
