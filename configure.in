# $Id: configure.in,v 1.11 2008/11/24 19:56:48 roesch Exp $

AC_INIT(daemonlogger.c)

AM_INIT_AUTOMAKE(daemonlogger, 1.2.1)
AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_CANONICAL_HOST

linux=no
sunos4=no

case "$host" in
  *-openbsd2.6|*-openbsd2.5|*-openbsd2.4|*-openbsd2.3*)
    AC_DEFINE(OPENBSD,,[Define if OPENBSD])
    AC_DEFINE(BROKEN_SIOCGIFMTU,,[Define if BROKEN_SIOCGIFMTU])

    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD)

    ;;
  *-sgi-irix5*)
    AC_DEFINE(IRIX,,[Define if IRIX])
    if test -z "$GCC"; then
      sgi_cc=yes
    fi
    LDFLAGS=${LDFLAGS} -L/usr/local/lib
    extra_incl=-I/usr/local/include
    ;;
  *-sgi-irix6*)
    AC_DEFINE(IRIX)
    if test -z "$GCC"; then
      sgi_cc=yes
    fi
    LDFLAGS=${LDFLAGS} -L/usr/local/lib
    extra_incl=-I/usr/local/include
    ;;
  *-solaris*)
    AC_DEFINE(SOLARIS,,[Define if SOLARIS])
    CPPFLAGS="${CPPFLAGS} -DBSD_COMP -D_REENTRANT"
    ;;
  *-sunos*)
    AC_DEFINE(SUNOS,,[Define if SUNOS])
    sunos4=yes
    ;;
  *-linux*)
    linux=yes
    AC_DEFINE(LINUX,,[Define if LINUX])
    if test -d "/usr/local/lib"; then
        LDFLAGS=${LDFLAGS} -L/usr/local/lib
    fi
    if test -d "/usr/include/pcap"; then
        AC_SUBST(extra_incl)
        extra_incl=-I/usr/include/pcap
    fi
    ;;
  *-hpux10*)
    AC_DEFINE(HPUX,,[Define if HPUX])
    AC_SUBST(extra_incl)
    extra_incl=-I/usr/local/include
    ;;

  *-freebsd*)
    AC_DEFINE(FREEBSD,,[Define if FREEBSD])

    ;;
  *-bsdi*)
    AC_DEFINE(BSDI,,[Define if BSDI])
    ;;
  *-aix*)
    AC_DEFINE(AIX,,[Define if AIX])
     broken_types=yes
    ;;
  *-osf4*)
    AC_DEFINE(OSF1,,[Define if OSF1])
    tru64_types=yes
    ;;
  *-osf5.1*)
    AC_DEFINE(OSF1)
    ;;
  *-tru64*)
    AC_DEFINE(OSF1)
    tru64_types=yes
    ;;
  *-apple*)
    AC_DEFINE(MACOS,,[Define if MACOS])
    AC_DEFINE(BROKEN_SIOCGIFMTU)
    if test -d "/sw"; then
      LDFLAGS="${LDFLAGS} -L/sw/lib"
      extra_incl="-I/sw/include"
    fi
    if test -d "/opt/local"; then
      LDFLAGS="${LDFLAGS} -L/opt/local/lib"
      extra_incl="-I/opt/local/include"
    fi
esac

if test "$prefix" = "NONE"; then
    prefix="/usr/local"
fi

AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_HEADERS(stdio.h stdlib.h stdarg.h errno.h getopt.h unistd.h \
                 fcntl.h string.h signal.h time.h limits.h)
AC_CHECK_HEADERS(sys/types.h sys/stat.h sys/time.h sys/queue.h)
if test "x$ac_cv_header_sys_queue_h" = "xyes"; then
    AC_MSG_CHECKING(for TAILQ_FOREACH in sys/queue.h)
    AC_EGREP_CPP(yes,
[
#include <sys/queue.h>
#ifdef TAILQ_FOREACH
 yes
#endif
],  [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_TAILQFOREACH, 1,
         [Define if TAILQ_FOREACH is defined in <sys/queue.h>])],
    AC_MSG_RESULT(no)
    )
fi

AC_CHECK_HEADERS(arpa/inet.h)

AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_PROG_GCC_TRADITIONAL
if test "$GCC" = yes ; then
    CFLAGS="$CFLAGS -g -O0 -Wall"
fi

LDFLAGS="${LDFLAGS} `dnet-config --libs`"
CFLAGS="${CFLAGS} `dnet-config --cflags`"
LDNET=""
AC_CHECK_LIB(dnet, intf_open,, LDNET="no")
echo "LDFLAGS set to $LDFLAGS"
echo "CFLAGS set to $CFLAGS"

if test "$LDNET" = "no"; then
   echo
   echo "   ERROR!  Libdnet library/headers not found, go get it from"
   echo "   http://libdnet.sourceforge.net"
   exit
fi

AC_CHECK_HEADERS(sys/queue.h)

AC_ARG_WITH(libpcap_includes,
	[  --with-libpcap-includes=DIR  libpcap include directory],
	[with_libpcap_includes="$withval"],[with_libpcap_includes=no])

AC_ARG_WITH(libpcap_libraries,
	[  --with-libpcap-libraries=DIR  libpcap library directory],
	[with_libpcap_libraries="$withval"],[with_libpcap_libraries=no])


if test "$with_libpcap_includes" != "no"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi

if test "$with_libpcap_libraries" != "no"; then
   LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
fi

LPCAP=""
AC_CHECK_LIB(pcap, pcap_datalink,, LPCAP="no")

if test "$LPCAP" = "no"; then
  echo
  echo "   ERROR!  Libpcap library/headers not found, go get it from"
  echo "   http://www.tcpdump.org"
  echo "   or use the --with-libpcap-* options, if you have it installed"
  echo "   in unusual place"
  exit 1
fi

AC_OUTPUT(Makefile)

