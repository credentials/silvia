# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

inherit autotools-utils git-2

DESCRIPTION="SImple Library for the Verification and Issuance of Attributes"
HOMEPAGE="https://github.com/credentials/silvia"
EGIT_REPO_URI="https://github.com/credentials/silvia"

LICENSE="BSD"
SLOT="0"
KEYWORDS=""
IUSE="test"

RDEPEND="
	=dev-libs/gmp-5*[cxx]
	dev-libs/openssl"
DEPEND="${RDEPEND}
	test? ( dev-util/cppunit )"

AUTOTOOLS_AUTORECONF=1
AUTOTOOLS_PRUNE_LIBTOOL_FILES=all
