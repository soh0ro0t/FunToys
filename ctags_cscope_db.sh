#! /bin/bash

echo "正在生成tags文件"
/usr/bin/ctags -R --fields=+lS .
if [[ $? == 0 ]]; then
	echo "生成tags文件成功"
	echo "$(readlink -f tags)"
else
echo "生成tags文件失败"
fi

echo "正在生成cscope.out"
find . \
	-name "out" -prune \
	-o -iname "*.s" -o -iname "*.h" \
	-o -iname "*.c" -o -name "*.cc" \
	-o -iname "*.cpp" -o -iname "*.cxx" \
  -o -iname "*.java" \
	| sed -n "s%^\.%$PWD%p" \
	> cscope.files
	
/usr/bin/cscope -Rbq
if [[ $? == 0 ]]; then
	echo "生成cscope.out成功"
	echo "$(readlink -f cscope.out)"
else	
	echo "生成cscope.out失败"
fi
