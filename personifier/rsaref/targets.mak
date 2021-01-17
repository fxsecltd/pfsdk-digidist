desc.$(O) : $(PRSDIR)desc.c $(PRSDIR)global.h $(PRSDIR)rsaref.h\
  $(PRSDIR)des.h
	$(CC) $(CFLAGS) $(PRSDIR)desc.c

digit.$(O) : $(PRSDIR)digit.c $(PRSDIR)global.h $(PRSDIR)rsaref.h\
  $(PRSDIR)nn.h $(PRSDIR)digit.h
	$(CC) $(CFLAGS) $(PRSDIR)digit.c

md2c.$(O) : $(PRSDIR)md2c.c $(PRSDIR)global.h $(PRSDIR)md2.h
	$(CC) $(CFLAGS) $(PRSDIR)md2c.c

md5c.$(O) : $(PRSDIR)md5c.c $(PRSDIR)global.h $(PRSDIR)md5.h
	$(CC) $(CFLAGS) $(PRSDIR)md5c.c

nn.$(O) : $(PRSDIR)nn.c $(PRSDIR)global.h $(PRSDIR)rsaref.h\
  $(PRSDIR)nn.h $(PRSDIR)digit.h
	$(CC) $(CFLAGS) $(PRSDIR)nn.c

prime.$(O) : $(PRSDIR)prime.c $(PRSDIR)global.h $(PRSDIR)rsaref.h\
  $(PRSDIR)r_random.h $(PRSDIR)nn.h $(PRSDIR)prime.h
	$(CC) $(CFLAGS) $(RSAREFDIR)prime.c

rsa.$(O) : $(RSAREFDIR)rsa.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h\
  $(RSAREFDIR)r_random.h $(RSAREFDIR)rsa.h $(RSAREFDIR)nn.h
	$(CC) $(CFLAGS) $(RSAREFDIR)rsa.c

r_dh.$(O) : $(RSAREFDIR)r_dh.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)nn.h\
  $(RSAREFDIR)prime.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_dh.c

r_encode.$(O) : $(RSAREFDIR)r_encode.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_encode.c

r_enhanc.$(O) : $(RSAREFDIR)r_enhanc.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)rsa.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_enhanc.c

r_keygen.$(O) : $(RSAREFDIR)r_keygen.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)nn.h\
  $(RSAREFDIR)prime.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_keygen.c

r_random.$(O) : $(RSAREFDIR)r_random.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)md5.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_random.c

r_stdlib.$(O) : $(RSAREFDIR)r_stdlib.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_stdlib.c

# Dependencies for header files

$(RSAREDIR)rsaref.h : $(RSAREFDIR)md2.h $(RSAREFDIR)md5.h $(RSAREFDIR)des.h
