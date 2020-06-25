systemddir = @SYSTEMD_DIR@

if RRR_SYSTEMD_NO_INSTALL
else
systemd_DATA = rrr.service
endif

install-data-local:
	chmod +x make-service.sh && ./make-service.sh rrr.service @bindir@ @RRR_CONF_DIR@

clean-local:
	echo "# DO NOT DELETE THIS FILE" > rrr.service

distclean-local:
	rm -f make-service.sh || true

