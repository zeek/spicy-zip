# @TEST-EXEC: zeek -Cr ${TRACES}/zip64.pcap %INPUT
# @TEST-EXEC: cat weird.log | zeek-cut name

# spicy-1.4 changed the rendering of parse errors, allow for that by bringing
# the log to that format even for older versions.
#
# TODO(bbannier): Remove this workaround once we stop supporting <spicy-1.4.
# @TEST-EXEC: cat .stdout | sed 's/^parse error: //g' >>output

# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Feed a ZIP64 archive into the ZIP, which is currently not supported but will reported

@load analyzer

event ZIP::file(f: fa_file, meta: ZIP::File) {
	print meta;
}

event ZIP::end_of_directory(f: fa_file, comment: string) {
	print comment;
}
