
#!/usr/bin/python
import os
import sys


# base functions
def issyn():
    return "tcp.flags == 2"

def cor(one, two):
    if one == "":
        return two
    if two == "":
        return one
    return "("+one+") or ("+two+")"

# join array of conditions with and
def aand(carr):
    out = ""
    if len(carr) == 0:
        return ""
    for elem in carr:
        out = out + ""+elem+" and "
    
    # remove last " and "
    out = out[:-5]
    return out

def aor(carr):
    out = ""
    if len(carr) == 0:
        return ""
    for elem in carr:
        out = out + "("+elem+") or "
    
    # remove last " and "
    out = "("+out[:-4]+")"
    return out


def cand(one, two):
    if one == "":
        return two
    if two == "":
        return one
    return ""+one+" and "+two+""

def equals(key, value):
    return key+"=="+value

def contains(key, value):
    return key+"contains"+value

def matchttl(value):
    if value == "*":
        return ""

    value = value.rstrip("-")
    val = int(value)
    if val < 65:
        return "ip.ttl < 65"
    elif val > 64 and val < 129:
        return "ip.ttl < 129 and ip.ttl>64"
    elif value > 128:
        return "ip.ttl > 128"
    else:
        return ""

# match using hdr_len but base len is 20 so we have to add given value
def matchipolen(value):
    if value == "*":
        return ""
    return "ip.hdr_len=="+str(20+int(value))

def matchmss(value):
    if value == "*":
        return ""
    return "tcp.options.mss_val=="+value

def matchwsize(value, mss, scaling, mtus):
    out = ""
    mtucond = []

    if value == "*":
        return ""

    # multiples of mss
    if "*" in value :
        if mss == "":
            return "Error in rule: mss unknown for window size rule based on mss"
        mssstr = value.split("*")[0]
        factor = value.split("*")[1]
        # ip and tcp headers, for now 40 bytes default
        if "mtu" in mssstr:
            headers = 0
        elif "mss" in mssstr:
            headers = 40

        # Not implemented yet, just set mss to 1460 for now
        if "mss" in mssstr or "mtu" in mssstr:
            if mss == "*":
                for size in mtus:
                    # TODO for now just substract 40 from mtu to get mss
                    calculated = int(size-headers)*int(factor)
                    # also we can not have an initial wsize over 65535
                    if calculated<=65535:
                        mtucond.append("tcp.window_size_value=="+str(calculated))
            else:
                #TODO calculate if mss is givem in tcp options
                calculated = str(int(mss)*int(factor))
                if calculated<=65535:
                    mtucond.append("tcp.window_size_value=="+calculated)
        else:
            #TODO support mtu and %4096 als
            #TODO support mtu and %4096 alsoo
            print "Errror unsupported operation in match wsize: "+mssstr
            sys.exit(1)




    else:
        wsize = value.split(",")[0]
        out = "tcp.window_size_value=="+wsize

    out = aor(mtucond)
    if (scaling != "" and scaling != "*"):
        out = cand(out,"tcp.options.wscale.shift=="+scaling)

    return out

def matchtcplayout(layout):
    ostr = ""
    filter = ""
    start = 0
    num = 0
    filters = []

    for option in layout:
        if "eol" in option:
            # accounting for eol
            ostr = "00:"
            start = start+1

            # accounting for padding
            numeol = int(option.split("+")[1])

            for _ in range(numeol):
                ostr = ostr + "00:"

            start = start+numeol
        elif option == "nop":
            ostr = ostr + "01:"
        elif option == "mss":
            #
            ostr = ostr + "02:04:" # XX:YY for mss value but we ignroe that
            # length in bytes
            num = len(ostr)/3
            filter = "tcp.options["+str(start)+":"+str(num)+"] == "+ostr[:-1]
            start = start+num+2
            filters.append(filter) 
            ostr = ""
        elif option == "ws":
            ostr = ostr + "03:03:"#XX:"
            num = len(ostr)/3
            filter = "tcp.options["+str(start)+":"+str(num)+"] == "+ostr[:-1]
            start = start+num+1
            filters.append(filter) 
            ostr = ""
        elif option == "sok":
            ostr = ostr + "04:02:"
        elif option == "sack":
            ostr = ostr + "05:0a:" #XX:XX:XX:XX:YY:YY:YY:YY"
            num = len(ostr)/3
            filter = "tcp.options["+str(start)+":"+str(num)+"] == "+ostr[:-1]
            start = start+num+8
            filters.append(filter) 
            ostr = ""
        elif option == "ts":
            ostr = ostr + "08:0a:" #XX:XX:XX:XX:YY:YY:YY:YY"
            num = len(ostr)/3
            filter = "tcp.options["+str(start)+":"+str(num)+"] == "+ostr[:-1]
            start = start+num+8
            filters.append(filter) 
            ostr = ""
        elif option == "?n":
            print "Caution verify if this works, as this does not consider"+\
            "length of the unknown option, which is unknown, as the unknown"+\
            "option... not sure how this is meant"

            unknownid = option.split("?")[1]
            strhex = "%0.2x" % unknownid
            ostr = ostr + strhex + ":"
        else:
            print "TCP Layout option not supported: "+option
   

    # remove last :
    # last ftiler
    if ostr != "":
        num = len(ostr)/3
        filter = "tcp.options ["+str(start)+":"+str(num)+"] == "+ostr[:-1] 
        filters.append(filter)

    out = aand(filters)
    return out


def matchtquirks(quirks):
    conditions = []
    for quirk in quirks:
        #ipv4 quirks
        if quirk == "df":
            conditions.append("ip.flags.df==1")
        elif quirk == "id+":
            conditions.append("ip.flags.df==1 and !ip.id==0")
        elif quirk == "id-":
            conditions.append("ip.flags.df==0 and !ip.id==0")
        elif quirk == "ecn":
            conditions.append("ip.dsfield.ecn == 1 or ip.dsfield.ecn==0")
        elif quirk == "0+":
            # must be zero of TOS is nowadays DSCP ECN low bit
            # TODO verify
            conditions.append("ip.dsfield.ecn == 0 or ip.dsfield.ecn == 2")

        #ipv6 quirks
        elif quirk == "flow":
            conditions.append("!ipv6.flow == 0")

        #tcp quirks
        elif quirk == "seq-":
            # tcp.seq == 0 would depend on relative or absolute seq number
            # setting in wireshark, this is independent
            conditions.append("tcp[4:4] == 00:00:00:00")
        elif quirk == "ack+":
            conditions.append("tcp[8:4] == 00:00:00:00 and tcp.flags.ack == 0")
        elif quirk == "ack-":
            conditions.append("tcp[8:4] == 00:00:00:00 and tcp.flags.ack == 1")
        elif quirk == "uptr+":
            conditions.append("!tcp.urgent_pointer == 0 and tcp.flags.urg == 1")
        elif quirk == "urgf+":
            conditions.append("tcp.flags.urg == 1")
        elif quirk == "pushf":
            conditions.append("tcp.flags.psh == 1")


        #tcp options quirks
        elif quirk == "ts1-":
            conditions.append("tcp.options.timestamp.tsval == 0")
        elif quirk == "ts2+":
            conditions.append("tcp.options.timestamp.tsval == 0 and tcp.flags == 2")
        elif quirk == "opt+":
            print "Error: opt+ quirk unsupported"
        elif quirk == "exws":
            conditions.append("tcp.options.wscale.shift > 14")
        elif quirk == "bad":
            print "Error: bad quirk unsupported"
        elif quirk == "":
            continue
        else:
            print "Error: could not decode quirks options: "+quirk

    # join and return conditions
    return aand(conditions)

def matchpclass(pclass):
    if "*" in pclass:
        return ""
    if "+" in pclass:
        return "tcp.len>0"
    if "0" in pclass:
        return "tcp.len==0"
    return ""


def convert(file):

    mtus = []
    fd = open(file)
    lines = fd.readlines()
    for line in lines:
        if "label" in line and ":" in line:
            os = line.split("=")[1].split(":")[2]
            version = line.split("=")[1].split(":")[3].rstrip()
            lastlabel=os+":"+version

        #mtu signature
        if "sig " in line and not ":" in line:
            mtus.append(int(line.split("=")[1]))

        if "sig " in line and ("nop" in line or "mss" in line or "ts" in line):
            tokens = line.split(":")

            outstr = issyn()
            
            matchversion = tokens[0].split("=")[1].lstrip()

            ittl = tokens[1]
            outstr = cand(outstr, matchttl(ittl))

            ipolen = tokens[2]
            outstr = cand(outstr, matchipolen(ipolen))

            mss = tokens[3]
            outstr = cand(outstr, matchmss(mss))

            window_options = tokens[4]
            wsize = window_options.split(",")[0]
            scale = window_options.split(",")[1]
            outstr = cand(outstr, matchwsize(wsize, mss, scale, mtus))

            tcpolayout = tokens[5].split(",")
            outstr = cand(outstr, matchtcplayout(tcpolayout))

            quirks = tokens[6].split(",")
            outstr = cand(outstr, matchtquirks(quirks))

            pclass = tokens[7]
            outstr = cand(outstr, matchpclass(pclass))
            
            print "@"+lastlabel+"@"+outstr+"@[65535,0,0][0,0,0]"
    
    return

def main(stdin=sys.stdin, args=sys.argv):    
    convert(args[1])

if __name__ == "__main__":
    main()
