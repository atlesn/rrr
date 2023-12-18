function myfun(a)
	print(a);
end

for i=1,#arg do
	myfun(arg[i])
end
