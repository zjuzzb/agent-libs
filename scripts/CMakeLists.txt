configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

configure_file(rpm/dragent.in rpm/dragent @ONLY)
configure_file(rpm/postinstall.in rpm/postinstall @ONLY)
configure_file(rpm/preuninstall.in rpm/preuninstall @ONLY)
