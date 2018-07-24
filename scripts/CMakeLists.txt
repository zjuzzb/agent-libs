configure_file(debian/dragent.in debian/dragent)
configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

configure_file(rpm/dragent.in rpm/dragent @ONLY)
