#!/usr/bin/python


# to generate the template list do:
# tshark -G fields > tsharkfields
# cat tsharkfields |awk -F"\t" '{print "\""$4"\" : \"text\"," }' | sort | uniq
#
wireshark_ignore = [
	"_ws_short",
	"_ws_malformed",
	"_ws_unreassembled",
	"_ws_malformed_dissector_bug",
	"_ws_malformed_reassembly",
	"_ws_malformed_expert",
	"_ws_type_length",
	"_ws_type_length_mismatch",
	"_ws_number_string_decoding_error",
	"_ws_number_string_decoding_error_failed",
	"_ws_number_string_decoding_error_erange"
]


dissectors = [
	"tcp",
	"ip",
	"eth"
]

wireshark_to_elastic_types = {
"" : "text",
"FT_ABSOLUTE_TIME" : "text",
"FT_AX25" : "text",
"FT_BOOLEAN" : "boolean",
"FT_BYTES" : "text",
"FT_DOUBLE" : "double",
"FT_ETHER" : "text",
"FT_EUI64" : "text",
"FT_FCWWN" : "text",
"FT_FLOAT" : "float",
"FT_FRAMENUM" : "text",
"FT_GUID" : "text",
"FT_IEEE_11073_FLOAT" : "text",
"FT_IEEE_11073_SFLOAT" : "text",
"FT_INT16" : "short",
"FT_INT24" : "text",
"FT_INT32" : "integer",
"FT_INT64" : "long",
"FT_INT8" : "byte",
"FT_IPXNET" : "text",
"FT_IPv4" : "ip",
"FT_IPv6" : "ip",
"FT_NONE" : "text",
"FT_OID" : "text",
"FT_PROTOCOL" : "text",
"FT_RELATIVE_TIME" : "text",
"FT_REL_OID" : "text",
"FT_STRING" : "text",
"FT_STRINGZ" : "text",
"FT_STRINGZPAD" : "text",
"FT_SYSTEM_ID" : "text",
"FT_UINT16" : "short",
"FT_UINT24" : "integer",
"FT_UINT32" : "integer",
"FT_UINT40" : "long",
"FT_UINT48" : "long",
"FT_UINT64" : "long",
"FT_UINT8" : "byte",
"FT_UINT_BYTES" : "text",
"FT_UINT_STRING" : "text",
"FT_VINES" : "text",
}


preamble = """{
    "mappings": {
      "pcap_file": {
        "properties": {
          "layers": {
            "properties": {
"""

imbetween ="""
              "tcp_dstport": {
                "type": "short",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
"""


tailer = """

                 }
                }
              }
            }
          },

          "timestamp": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          }
        }
      }
    }
}
"""

# extract tshark field types
# tshark -G fields  |awk -F"\t" '{print $3","$4","$2}' | sort > sortedfields

import csv

import sys
sys.stdout.write(preamble)

first = True
last = False

firstafterproto = True

countelements = 0

with open('ethernet.mapping', 'r') as csvfile:
	fieldreader = csv.reader(csvfile, delimiter=',')
	for row in fieldreader:
		# elastic default in put from tshark ek is underscores so we have to adapt
		displayfilter = row[0].replace(".","_")
		tsharktype = row[1]
		description = row[2]
		elastictype = wireshark_to_elastic_types[tsharktype]

		# ignore strange types
		if displayfilter in wireshark_ignore:
			continue

		# check if it is a new protocol
		if not "_" in displayfilter:

			if displayfilter not in dissectors:
				continue


			firstafterproto = True
			if not first:
				if not countelements == 0:
					print "                		}"	

				print "                }"
				print "              },"
			else:
				first=False

			countelements = 0
			print "              \""+displayfilter+"\": {"
			print "                \"properties\": {"

		else:
			doit = False
			for dissector in dissectors:
				if displayfilter.startswith(dissector+"_"):
					doit=True

			if doit == False:
				continue

			countelements = countelements + 1
			if firstafterproto:
				firstafterproto = False
			else:
				print "                  },"	
				
			# default to text
			if elastictype == None:
				elastictype = "text"

			print "                  \""+displayfilter+"\": {"
			print "                    \"type\": \""+elastictype+"\""



print tailer

