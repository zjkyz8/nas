#!/bin/bash

NAME=aliddns
log_file=/var/log/ddns.log

uci_get_by_name() {
	local ret=$(uci get $NAME.$1.$2 2>/dev/null)
	echo -n ${ret:=$3}
}

uci_bool_by_name() {
	case "$(uci_get_by_name $1 $2)" in
		1|on|true|yes|enabled) return 0;;
	esac
	return 1
}

intelnetip() {
	tmp_ip=`curl -sL --connect-timeout 3   ns1.dnspod.net:6666`
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`curl -sL --connect-timeout 3 members.3322.org/dyndns/getip`
	fi
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`curl -sL --connect-timeout 3 14.215.150.17:6666`
	fi
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`curl -sL --connect-timeout 3 whatismyip.akamai.com`
	fi
	echo -n $tmp_ip
}
intelnetip6() {
	tmp_ip6=`curl -sL --connect-timeout 3   v6.ident.me`
	echo $tmp_ip6
}

resolve2ip() {
	# resolve2ip domain<string>
	domain=$1
	tmp_ip=`nslookup -type=A $domain ns1.alidns.com 2>/dev/null | sed '/^Server/d; /#53$/d' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -n1`
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`nslookup -type=A $domain ns2.alidns.com  2>/dev/null | sed '/^Server/d; /#53$/d' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -n1`
	fi
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`nslookup $domain 114.114.115.115 2>/dev/null | sed '/^Server/d; /#53$/d' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -n1`
	fi
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`curl -sL --connect-timeout 3 "119.29.29.29/d?dn=$domain"`
	fi
	echo -n $tmp_ip
}

resolve2ipv6() {
	domain=$1
	tmp_ip6=`nslookup -type=AAAA $domain ns1.alidns.com 2>/dev/null | sed '/^Server/d; /#53$/d' | grep -oE '([0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4}' | tail -n1`
	if [ "Z$tmp_ip" == "Z" ]; then
		tmp_ip=`nslookup -type=AAAA $domain ns2.alidns.com  2>/dev/null | sed '/^Server/d; /#53$/d' | grep -oE '([0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4}' | tail -n1`
	fi
	echo -n $tmp_ip6
}

check_aliddns() {
	echo "$DATE WAN-IP: ${ip}"
	if [ "Z$ip" == "Z" ]; then
		echo "$DATE ERROR, cant get WAN-IP..."
		return 0
	fi
	if [ "Z$type" == "ZAAAA" ]; then
		current_ip=$(resolve2ipv6 "$sub_dm.$main_dm")
	fi
	if [ "Z$type" == "ZA" ]; then
		current_ip=$(resolve2ip "$sub_dm.$main_dm")
	fi
	if [ "Z$current_ip" == "Z" ]; then
		rrid='' # NO Resolve IP Means new Record_ID
	fi
	echo "$DATE DOMAIN-IP: ${current_ip}"
	if [ "Z$ip" == "Z$current_ip" ]; then
		echo "$DATE IP dont need UPDATE..."
		return 0
	else
		echo "$DATE UPDATING..."
		return 1
	fi
}

urlencode() {
	# urlencode url<string>
	out=''
	for (( i=0; i<${#1}; i++ )); do
		c="${1:$i:1}"
		case $c in
			[a-zA-Z0-9._-]) out="$out$c" ;;
			*) out="$out$(printf '%%%02X' "'$c")" ;;
		esac
	done
	# for c in $(echo $1 | sed 's/\(.\)/\1\n/g'); do
	# 	echo "$c" > log
	# 	case $c in
	# 		[a-zA-Z0-9._-]) out="$out$c" ;;
	# 		*) out="$out$(printf '%%%02X' "'$c")" ;;
	# 	esac
	# done
	echo -n $out
}

send_request() {
	# send_request action<string> args<string>
	local args="AccessKeyId=$ak_id&Action=$1&Format=json&$2&Version=2015-01-09"
	local hash=$(urlencode $(echo -n "GET&%2F&$(urlencode $args)" | openssl dgst -sha1 -hmac "$ak_sec&" -binary | openssl base64))
	curl -sSL --connect-timeout 5 "http://alidns.aliyuncs.com/?$args&Signature=$hash"
}

get_recordid() {
	sed 's/RR/\n/g' | sed -n 's/.*RecordId[^0-9]*\([0-9]*\).*/\1/p' | sort -ru | sed /^$/d
}

query_recordid() {
	send_request "DescribeSubDomainRecords" "SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&SubDomain=$sub_dm.$main_dm&Timestamp=$timestamp&Type=$type"
}

update_record() {
	send_request "UpdateDomainRecord" "RR=$sub_dm&RecordId=$1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&Timestamp=$timestamp&Type=$type&Value=`urlencode $ip`"
}

add_record() {
	send_request "AddDomainRecord&DomainName=$main_dm" "RR=$sub_dm&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&Timestamp=$timestamp&Type=$type&Value=`urlencode $ip`"
}

del_record() {
	send_request "DeleteDomainRecord" "RecordId=$1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&Timestamp=$timestamp"
}

do_ddns_record() {
	# if uci_bool_by_name base clean ; then
	# 	query_recordid | get_recordid | while read rr; do
	# 		echo "$DATE Clean record $sub_dm.$main_dm: $rr"
	# 		del_record $rr >/dev/null
	# 		timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")
	# 	done
	# 	rrid=''
	# fi
	if [ "Z$rrid" == "Z" ]; then
		rrid=`query_recordid | get_recordid`
	fi
	if [ "Z$rrid" == "Z" ]; then
		rrid=`add_record | get_recordid`
		echo "$DATE ADD record $rrid"
	else
		update_record $rrid >/dev/null 2>&1
		echo "$DATE UPDATE record $rrid"
	fi
	if [ "Z$rrid" == "Z" ]; then
		# failed
		echo "$DATE # ERROR, Please Check Config/Time"
	else
		# save rrid
		# uci set aliddns.base.record_id=$rrid
		# uci commit aliddns
		echo "$DATE # UPDATED($ip)"
	fi
}

clean_log() {
	if [ $(cat $log_file 2>/dev/null | wc -l) -ge 16 ]; then
		rm -f $log_file && touch $log_file
		echo "$DATE Log Cleaned"
	fi
}

ak_id=$1
ak_sec=$2
rrid=""
main_dm=$3
sub_dm=$4

protocol=IPv6

if [ "Z$protocol" == "ZIPv6" ]; then
	ip=$(intelnetip6)
	type='AAAA'
else
	ip=$(intelnetip)
	type='A'
fi

DATE=$(date +'%Y-%m-%d %H:%M:%S')
timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")

clean_log
check_aliddns || do_ddns_record