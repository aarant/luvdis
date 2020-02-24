from setuptools import setup

from luvdis import __version__, url

with open('README.md', 'r') as f:
    long_description = f.read()


setup(name='Luvdis',
      version=__version__,
      description='Pure-Python Game Boy Advance Disassembler',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Ariel Antonitis',
      author_email='arant@mit.edu',
      url=url,
      packages=['luvdis', 'luvdis.test'],
      package_data={'luvdis': ['*.inc']},  # Include embedded functions
      include_package_data=True,
      entry_points={'console_scripts': ['luvdis = luvdis.__main__:main']},
      license='MIT',
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Console',
                   'Topic :: Software Development :: Disassemblers',
                   'Topic :: System :: Hardware',
                   'Programming Language :: Python :: 3.6',
                   'Programming Language :: Python :: 3.7',
                   'Programming Language :: Python :: 3.8'],
      install_requires=[],
      python_requires='>=3.6')
