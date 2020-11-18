man1_MANS = man/rrr.1 man/rrr_post.1 man/rrr_stats.1 man/rrr_passwd.1 man/rrr_auth.1
man5_MANS = man/rrr.conf.5 man/rrr_python3.5
environmentfile_DATA = rrr.conf
environmentfiledir = @RRR_ENVIRONMENT_FILE_DIR@

if RRR_WITH_SYSTEMD
systemd_subdir = systemd
endif

if RRR_WITH_CONFDIR
confdir_subdir = confdir
endif

if RRR_WITH_RUNIT
runit_subdir = runit
endif

if RRR_WITH_OPENRC
openrc_subdir = openrc
endif

SUBDIRS = ${systemd_subdir} ${confdir_subdir} ${runit_subdir} ${openrc_subdir}
