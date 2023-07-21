Development
============

Requirements
------------

Rohmu requires Python >= 3.8. For Python library dependencies, have a
look at
`requirements.txt <https://github.com/aiven/rohmu/blob/main/requirements.txt>`__.


Building the package
--------------------

To build an installation package for your distribution, go to the root
directory of a Rohmu Git checkout and run:

Fedora::

  sudo make fedora-dev-setup
  make rpm

This will produce a ``.rpm`` package usually into ``rpm/RPMS/noarch/``.
