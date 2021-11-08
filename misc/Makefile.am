man1_MANS = man/rrr.1 man/rrr_post.1 man/rrr_stats.1 man/rrr_passwd.1 man/rrr_auth.1
man5_MANS = man/rrr.conf.5 man/rrr_python3.5
environmentfile_DATA = rrr.conf
environmentfiledir = @RRR_ENVIRONMENT_FILE_DIR@
varlibfile_DATA = .placeholder
varlibfiledir = @RRR_DATA_DIR@

SUBDIRS = systemd confdir runit openrc

install-data-hook:
	chown -R @RRR_DAEMON_USERNAME@:@RRR_DAEMON_USERNAME@ ${DESTDIR}${varlibfiledir} || true

