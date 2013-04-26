require 'formula'

class Openssl1 <Formula
  url 'http://www.openssl.org/source/openssl-1.0.1e.tar.gz'
  version '1.0.1e'
  homepage 'http://www.openssl.org'
  sha1 '3f1b1223c9e8189bfe4e186d86449775bd903460'

  def install
    args = %W[./Configure
               --prefix=#{prefix}
               --openssldir=#{etc}/openssl
               zlib-dynamic
               shared
             ]

    args << (MacOS.prefer_64_bit? ? "darwin64-x86_64-cc" : "darwin-i386-cc")

    system "perl", *args

    ENV.deparallelize # Parallel compilation fails
    system "make"
    #system "make", "test"
    system "make", "install", "MANDIR=#{man}", "MANSUFFIX=ssl"
  end

  def patches
    DATA
  end
end

__END__
diff --git a/apps/s_client.c b/apps/s_client.c
index 34ad2ce..12df5bf 100644
--- a/apps/s_client.c
+++ b/apps/s_client.c
@@ -329,16 +329,18 @@ static void sc_usage(void)
 	BIO_printf(bio_err," -starttls prot - use the STARTTLS command before starting TLS\n");
 	BIO_printf(bio_err,"                 for those protocols that support it, where\n");
 	BIO_printf(bio_err,"                 'prot' defines which one to assume.  Currently,\n");
-	BIO_printf(bio_err,"                 only \"smtp\", \"pop3\", \"imap\", \"ftp\" and \"xmpp\"\n");
-	BIO_printf(bio_err,"                 are supported.\n");
+    BIO_printf(bio_err,"                  only \"smtp\", \"pop3\", \"imap\", \"ftp\", \n");
+    BIO_printf(bio_err,"                  \"xmpp-client\", and \"xmpp-server\" are supported.\n");
 #ifndef OPENSSL_NO_ENGINE
 	BIO_printf(bio_err," -engine id    - Initialise and use the specified engine\n");
 #endif
 	BIO_printf(bio_err," -rand file%cfile%c...\n", LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);
 	BIO_printf(bio_err," -sess_out arg - file to write SSL session to\n");
 	BIO_printf(bio_err," -sess_in arg  - file to read SSL session from\n");
-#ifndef OPENSSL_NO_TLSEXT
 	BIO_printf(bio_err," -servername host  - Set TLS extension servername in ClientHello\n");
+    BIO_printf(bio_err,"                     (if extensons enabled), and used as the target\n");
+    BIO_printf(bio_err,"                     servername in XMPP starttls.\n");
+#ifndef OPENSSL_NO_TLSEXT
 	BIO_printf(bio_err," -tlsextdebug      - hex dump of all TLS extensions received\n");
 	BIO_printf(bio_err," -status           - request certificate status from server\n");
 	BIO_printf(bio_err," -no_ticket        - disable use of RFC4507bis session tickets\n");
@@ -375,7 +377,8 @@ enum
 	PROTO_POP3,
 	PROTO_IMAP,
 	PROTO_FTP,
-	PROTO_XMPP
+    PROTO_XMPP,
+    PROTO_XMPP_SERVER
 };
 
 int MAIN(int, char **);
@@ -425,8 +428,8 @@ int MAIN(int argc, char **argv)
 	int stdin_set = 0;
 #endif
 #endif
-#ifndef OPENSSL_NO_TLSEXT
 	char *servername = NULL; 
+#ifndef OPENSSL_NO_TLSEXT
         tlsextctx tlsextcbp = 
         {NULL,0};
 #endif
@@ -686,8 +689,14 @@ int MAIN(int argc, char **argv)
 				starttls_proto = PROTO_IMAP;
 			else if (strcmp(*argv,"ftp") == 0)
 				starttls_proto = PROTO_FTP;
+            /* backward-compatibility */
 			else if (strcmp(*argv, "xmpp") == 0)
 				starttls_proto = PROTO_XMPP;
+            /* go-forward, parallel with xmpp-server, same as the SRV records */
+            else if (strcmp(*argv, "xmpp-client") == 0)
+                starttls_proto = PROTO_XMPP;
+            else if (strcmp(*argv, "xmpp-server") == 0)
+                starttls_proto = PROTO_XMPP_SERVER;
 			else
 				goto bad;
 			}
@@ -708,14 +717,12 @@ int MAIN(int argc, char **argv)
 			if (--argc < 1) goto bad;
 			inrand= *(++argv);
 			}
-#ifndef OPENSSL_NO_TLSEXT
 		else if (strcmp(*argv,"-servername") == 0)
 			{
 			if (--argc < 1) goto bad;
 			servername= *(++argv);
 			/* meth=TLSv1_client_method(); */
 			}
-#endif
 #ifndef OPENSSL_NO_JPAKE
 		else if (strcmp(*argv,"-jpake") == 0)
 			{
@@ -1178,12 +1185,34 @@ SSL_set_tlsext_status_ids(con, ids);
 		BIO_printf(sbio,"AUTH TLS\r\n");
 		BIO_read(sbio,sbuf,BUFSIZZ);
 		}
-	if (starttls_proto == PROTO_XMPP)
+    else if (starttls_proto == PROTO_XMPP)
+        {
+        int seen = 0;
+        BIO_printf(sbio,"<stream:stream "
+            "xmlns:stream='http://etherx.jabber.org/streams' "
+            "xmlns='jabber:client' to='%s' version='1.0'>", servername ? servername : host);
+        seen = BIO_read(sbio,mbuf,BUFSIZZ);
+        mbuf[seen] = 0;
+        while (!strstr(mbuf, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'"))
+            {
+            if (strstr(mbuf, "/stream:features>"))
+                goto shut;
+            seen = BIO_read(sbio,mbuf,BUFSIZZ);
+            mbuf[seen] = 0;
+            }
+        BIO_printf(sbio, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
+        seen = BIO_read(sbio,sbuf,BUFSIZZ);
+        sbuf[seen] = 0;
+        if (!strstr(sbuf, "<proceed"))
+            goto shut;
+        mbuf[0] = 0;
+        }
+    else if (starttls_proto == PROTO_XMPP_SERVER)
 		{
 		int seen = 0;
 		BIO_printf(sbio,"<stream:stream "
 		    "xmlns:stream='http://etherx.jabber.org/streams' "
-		    "xmlns='jabber:client' to='%s' version='1.0'>", host);
+            "xmlns='jabber:server' to='%s' version='1.0'>", servername ? servername : host);
 		seen = BIO_read(sbio,mbuf,BUFSIZZ);
 		mbuf[seen] = 0;
 		while (!strstr(mbuf, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'"))
diff --git a/crypto/x509v3/v3_alt.c b/crypto/x509v3/v3_alt.c
index d29d943..0d19214 100644
--- a/crypto/x509v3/v3_alt.c
+++ b/crypto/x509v3/v3_alt.c
@@ -103,16 +103,72 @@ STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
 	return ret;
 }
 
+static int add_othername_string(const char *name, ASN1_STRING *asn1_string,
+                STACK_OF(CONF_VALUE) **extlist)
+{
+    unsigned char *string_buf = NULL;
+    int ret;
+    char subjectOther[128];
+    int string_len;
+    BIO_snprintf(subjectOther, sizeof(subjectOther), "othername(%s)", name);
+
+    if (!asn1_string)
+    {
+        return X509V3_add_value(subjectOther, "<unknown>", extlist);
+    }
+
+    string_len = ASN1_STRING_to_UTF8(&string_buf, asn1_string);
+    if (string_len >= 0)
+    {
+        ret = X509V3_add_value(subjectOther, string_buf, extlist);
+        OPENSSL_free(string_buf);
+    }
+    else
+    {
+        ret = X509V3_add_value(subjectOther, "<invalid>", extlist);
+    }
+    return ret;
+}
+
+/* returns 1 on match, 0 otherwise */
+static int check_oid(char *oid, char *name, ASN1_OBJECT *type_id, ASN1_STRING *value,
+                STACK_OF(CONF_VALUE) **extlist)
+{
+    ASN1_OBJECT *other_oid = OBJ_txt2obj(oid, 1);
+    if ((OBJ_cmp(type_id, other_oid)) == 0)
+    {
+        add_othername_string(name, value, extlist);
+        return 1;
+    }
+    return 0;
+}
+
 STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method,
 				GENERAL_NAME *gen, STACK_OF(CONF_VALUE) *ret)
 {
 	unsigned char *p;
 	char oline[256], htmp[5];
 	int i;
+    OTHERNAME *otherName = NULL;
+    char description[80];
+
 	switch (gen->type)
 	{
 		case GEN_OTHERNAME:
-		X509V3_add_value("othername","<unsupported>", &ret);
+        otherName = gen->d.otherName;
+        if (check_oid("1.3.6.1.5.5.7.8.1", "id-on-personalData", otherName->type_id, NULL, &ret) ||
+            check_oid("1.3.6.1.5.5.7.8.2", "id-on-userGroup", otherName->type_id, NULL, &ret) ||
+            check_oid("1.3.6.1.5.5.7.8.3", "id-on-permanentIdentifier", otherName->type_id, NULL, &ret) ||
+            check_oid("1.3.6.1.5.5.7.8.4", "id-on-hardwareModuleName", otherName->type_id, NULL, &ret) ||
+            check_oid("1.3.6.1.5.5.7.8.5", "id-on-xmppAddr", otherName->type_id, otherName->value->value.utf8string, &ret) ||
+            check_oid("1.3.6.1.5.5.7.8.6", "id-on-SIM", otherName->type_id, NULL, &ret) ||
+            check_oid("1.3.6.1.5.5.7.8.7", "id-on-dnsSRV", otherName->type_id, otherName->value->value.ia5string, &ret))
+        {
+            break;
+        }
+
+        OBJ_obj2txt(description, sizeof(description), otherName->type_id, 0);
+        add_othername_string(description, NULL, &ret);
 		break;
 
 		case GEN_X400:
@@ -178,6 +234,7 @@ int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen)
 {
 	unsigned char *p;
 	int i;
+
 	switch (gen->type)
 	{
 		case GEN_OTHERNAME:
diff --git a/doc/apps/s_client.pod b/doc/apps/s_client.pod
index 4ebf7b5..826aa48 100644
--- a/doc/apps/s_client.pod
+++ b/doc/apps/s_client.pod
@@ -203,7 +203,8 @@ command for more information.
 
 send the protocol-specific message(s) to switch to TLS for communication.
 B<protocol> is a keyword for the intended protocol.  Currently, the only
-supported keywords are "smtp", "pop3", "imap", and "ftp".
+supported keywords are "smtp", "pop3", "imap", "ftp", "xmpp-client", and 
+"xmpp-server".
 
 =item B<-tlsextdebug>
 
