#!/bin/sh

cd $(dirname "$0")

tmp=/tmp/batadv-check-tt-crc.tg
last=/tmp/batadv-check-tt-crc_last_res.txt
now=/tmp/batadv-check-tt-crc_now_res.txt

batctl tg -H > ${tmp}
python3 main.py ${tmp} | sort > ${now}

if [ -f ${last} ]; then
	diff -u --color=always ${last} ${now}
else
	echo "FIRST RUN!"
fi

mv ${now} ${last} 

