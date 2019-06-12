#!/bin/sh

export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/rrr

valgrind --leak-check=full rrr module=mysql,udpreader debuglevel=5 \
	udpr_port=2000 udpr_input_types=le,4,le,4,le,4,le,4,le,4,le,4,le,4,array,10,le,4,array,10,le,4 \
	mysql_user=root mysql_password=MgeBdQ mysql_db=cart-logger mysql_table=measurements \
	mysql_colplan=array mysql_columns=timer_1,timer_2,timer_3,timer_4,timer_5,timer_length,cart_id \
	mysql_add_timestamp_col=yes
