man1_MANS = man/rrr.1 man/rrr_post.1 man/rrr_stats.1 man/rrr_passwd.1 man/rrr_auth.1
man5_MANS = man/rrr.conf.5 man/rrr_python3.5
conf_DATA = rrr.conf
confdir = @sysconfdir@

if RRR_WITH_SYSTEMD
systemd_subdir = systemd
endif

if RRR_WITH_CONFDIR
confdir_subdir = confdir
endif

if RRR_WITH_RUNIT
runit_subdir = runit
endif

SUBDIRS = ${systemd_subdir} ${confdir_subdir} ${runit_subdir}
