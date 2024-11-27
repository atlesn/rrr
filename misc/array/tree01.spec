be1#type,be1#one
IF ({type} == 1)
	;
ELSIF ({type} == 2)
	REWIND1
	be2#two
	;
ELSIF ({type} > 0)
	REWIND1
	blob{type}#x
	;
ELSE
	err
	;
sep1#separator
;
x
xx
xxxxx
