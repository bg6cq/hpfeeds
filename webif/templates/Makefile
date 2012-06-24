all: base.html index.html
base.html: base.gb2312.html
	iconv -f gb2312 -t utf-8 -o base.html base.gb2312.html
index.html: index.gb2312.html
	iconv -f gb2312 -t utf-8 -o index.html index.gb2312.html
