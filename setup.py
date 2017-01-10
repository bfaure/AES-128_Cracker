from distutils.core import setup
from Cython.Build import cythonize

setup(
  name = 'C Utilities for Decrypting',
  ext_modules = cythonize("utils.pyx"),
)