#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ostree-upgrade], [0.0.0], [BUG-REPORT-ADDRESS])

AM_INIT_AUTOMAKE([-Wno-portability subdir-objects foreign])

AC_ARG_WITH(systemdunitdir,
  [AC_HELP_STRING([--with-systemdunitdir], [systemd unt directory])],
  [systemd_unitdir="${withval}"], [systemd_unitdir=${libdir}/systemd])

AC_SUBST(systemd_unitdir)

AC_OUTPUT([Makefile])

echo "Effective configuration:"
echo "* systemd unit directory: $systemd_unitdir"
