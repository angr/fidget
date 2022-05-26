from setuptools import setup

setup(name='Fidget',
      version='1.0',
      description='Binary mangling utility',
      author='rhelmot',
      packages=['fidget'],
      scripts=['script/fidget'],
      install_requires=[
          "angr",
          "ipdb",
          "shellphish-qemu",
          "nclib",
      ]
)
