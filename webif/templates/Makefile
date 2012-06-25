all: base.html index.html users.html channels.html settings.html
%.html: %.gb2312
	iconv -f gb2312 -t utf-8 -o $@ $<
