#!/bin/sh

export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/rrr

valgrind --leak-check=full rrr module=mysql,udpreader debuglevel=5 \
	udpr_port=2000 udpr_input_types=be,4,be,4,be,4,be,4,be,4,be,4,be,4,array,10,be,4,array,10,be,4,be,4 \
	mysql_user=cartmeasure mysql_password=t59YgpW9mZlS8oAF mysql_db=cartmeasure mysql_table=input_data \
	mysql_colplan=array mysql_columns=time_1,time_2,time_3,time_4,time_5,time_total,cart_id,heights_left,heights_right,endian_indicator \
	mysql_special_columns=configuration,aths mysql_add_timestamp_col=yes
