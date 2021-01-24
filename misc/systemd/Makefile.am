systemd_unitdir = @RRR_SYSTEMD_UNIT_DIR@
systemd_tmpfilesdir = @RRR_TMPFILES_DIR@

if RRR_SYSTEMD_NO_UNIT_INSTALL
else
systemd_unit_DATA = rrr.service
endif

if RRR_SYSTEMD_NO_TMPFILES_INSTALL
else
systemd_tmpfiles_DATA = rrr.conf
endif

install-data-local:
	chmod +x make-service.sh && \
	./make-service.sh rrr.service @bindir@ @RRR_CONF_DIR@ @RRR_ENVIRONMENT_FILE_DIR@ && \
	chmod +x make-tmpfiles.sh && \
	./make-tmpfiles.sh rrr.conf

clean-local:
	echo "# DO NOT DELETE THIS FILE" > rrr.service && \
	echo "# DO NOT DELETE THIS FILE" > rrr.conf

distclean-local:
	rm -f make-service.sh make-tmpfiles.sh || true
