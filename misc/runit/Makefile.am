runitdir = @RUNIT_SV_DIR@
runit_SCRIPTS = run

install-data-local:
	chmod +x make-runit.sh && ./make-runit.sh run @bindir@ @RRR_CONF_DIR@ @libdir@ @sysconfdir@

install-exec-hook:
	ln -s /etc/sv/rrr /var/service/rrr

uninstall-hook:
	rm -f /var/service/rrr

clean-local:
	echo "# DO NOT DELETE THIS FILE" > run

distclean-local:
	rm -rf make-runit.sh || true

