spicy_add_analyzer(
    NAME Archive
    PACKAGE_NAME Archive
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek)
