KSRC=/usr/src/linux-headers-$(shell uname -r)
CFLAGS=-I$(KSRC)/include/uapi -I$(KSRC)/include -DPIC -fPIC -Wno-cpp
LDFLAGS=-lxtables -shared
XF_MODULE=libxt_SYNSANITY
XT_MATCH_MODULE=libxt_syncookies
XT_CONDITION_MODULE=libxt_condition
XT_CONDITION_TG_MODULE=libxt_CONDITION

.PHONY: lib
lib: $(XF_MODULE).so $(XT_MATCH_MODULE).so $(XT_CONDITION_MODULE).so

%.so: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm $(XF_MODULE).so $(XT_MATCH_MODULE).so $(XT_CONDITION_MODULE).so

.PHONY: install
install: lib
	install -d $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)
	install -m 0755 $(XF_MODULE).so $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)
	install -m 0755 $(XT_MATCH_MODULE).so $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)
	install -m 0755 $(XT_CONDITION_MODULE).so $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)
	install -m 0755 $(XT_CONDITION_MODULE).so $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)/$(XT_CONDITION_TG_MODULE).so