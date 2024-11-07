# @TEST-EXEC: zeek -C -r ${TRACES}/descriptor.pcap frameworks/files/extract-all-files frameworks/files/hash-all-files %INPUT
# @TEST-EXEC: for i in extract_files/*; do (printf "$i "; wc -c "$i" | awk '{print $1}'); done | sort >extracted.log
# @TEST-EXEC: for i in files.log extracted.log .stdout; do cat $i | sed 's#\(extract-[^-]*\)-[^-]*-#\1-xxx-#g' | sed 's#F[A-Za-z0-9]\{16,17\}#XXXXXXXXXXXXXXXXX#g' >$i.tmp && mv $i.tmp $i; done
#
# @TEST-EXEC: zeek-cut -Cn duration <files.log >files.log.tmp && mv files.log.tmp files.log
# @TEST-EXEC: btest-diff files.log
#
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff extracted.log
#
# @TEST-DOC: Test ZIP analyzer with a download of a ZIP file that uses a data descriptor.
#
# With the data descriptor, the file sizes comes only after the file content. Our
# ZIP archive stress-tests the heuristic for finding the end of the file content by
# containing a file that includes the terminator magic string inside its plain-text
# content.

@load analyzer

event ZIP::file(f: fa_file, meta: ZIP::File)
	{
	print meta;
	}

event ZIP::end_of_directory(f: fa_file, comment: string)
	{
	print comment;
	}
