short_ver = $(shell git describe --abbrev=0 --always)
long_ver = $(shell git describe --long 2>/dev/null || echo $(short_ver)-0-unknown-g`git describe --always`)

.DEFAULT_GOAL := rpm

.PHONY: fedora-dev-setup
fedora-dev-setup:
	dnf builddep -y rohmu.spec

.PHONY: rpm
rpm: rohmu/
	git archive --output=rohmu-rpm-src.tar --prefix=rohmu/ HEAD
	rpmbuild -bb rohmu.spec \
		--define '_topdir $(PWD)/rpm' \
		--define '_sourcedir $(CURDIR)' \
		--define 'major_version $(short_ver)' \
		--define 'minor_version $(subst -,.,$(subst $(short_ver)-,,$(long_ver)))'
	$(RM) rohmu-rpm-src.tar
