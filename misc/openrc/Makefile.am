openrcdir = /etc/init.d
openrc_SCRIPTS = rrr

install-data-local:
	chmod +x make-service.sh && ./make-service.sh rrr @bindir@ @RRR_CONF_DIR@ @libdir@ @sysconfdir@

uninstall-hook:
	rm -f /etc/init.d/rrr

clean-local:
	echo "# DO NOT DELETE THIS FILE" > rrr

distclean-local:
	rm -rf make-service.sh || true

