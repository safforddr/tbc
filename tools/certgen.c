/* 
 * certgen.c    
 *
 * compile:     gcc -o certgen certgen.c -lssl -lcrypto
 * ./certgen creates cert from AK.PEM, and signs with CA key and cert
 * output (in PEM) is written to stdout
 *
 * Be sure to set your O, CN, and paths as appropriate.
 *
 * Copyright (C) 2024
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

/* PATHS */
#define CACERT          "./certs/safford_ca.com.pem"
#define CAKEY           "./keys/private.pem"
#define PUBKEY          "./AK.PEM"

#define PASS            ""

BIO               *reqbio = NULL;
BIO               *outbio = NULL;
X509                *cert = NULL;
X509_REQ         *certreq = NULL;

int main() {

  ASN1_INTEGER                 *aserial = NULL;
  EVP_PKEY                     *ca_privkey, *req_pubkey;
  EVP_MD                       const *digest = NULL;
  X509                         *newcert, *cacert;
  X509_NAME                    *name;
  X509V3_CTX                   ctx;
  FILE                         *fp;
  long                         valid_secs = 31536000;

  // init openssl
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  outbio = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
  
  // load AK Public key
  req_pubkey = EVP_PKEY_new();  
  if (! (fp=fopen(PUBKEY, "r"))) {
      BIO_printf(outbio, "Error reading AK.PEM Public file\n");
      exit(-1);
  }
  if(! (req_pubkey = PEM_read_PUBKEY(fp,NULL,NULL,NULL))) {
      BIO_printf(outbio, "Error loading AK into memory\n");
      exit(-1);
  }
  fclose(fp);
  
  // load CA Cert
  if (! (fp=fopen(CACERT, "r"))) {
      BIO_printf(outbio, "Error reading CA cert file\n");
      exit(-1);
  }
  if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL))) {
      BIO_printf(outbio, "Error loading CA cert into memory\n");
      exit(-1);
  }
  fclose(fp);

  // load CA Private Key
  ca_privkey = EVP_PKEY_new();
  if (! (fp = fopen (CAKEY, "r"))) {
      BIO_printf(outbio, "Error reading CA private key file\n");
      exit(-1);
  }
  if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS))) {
      BIO_printf(outbio, "Error importing key content from file\n");
      exit(-1);
  }
  fclose(fp);

  /* Build Certificate with data from request */
  if (! (newcert=X509_new())) {
      BIO_printf(outbio, "Error creating new X509 object\n");
      exit(-1);
  }
  if (X509_set_version(newcert, 2) != 1) {
      BIO_printf(outbio, "Error setting certificate version\n");
      exit(-1);
  }

  /* set the certificate serial number */
  aserial=ASN1_INTEGER_new();
  ASN1_INTEGER_set(aserial, 0);
  if (! X509_set_serialNumber(newcert, aserial)) {
      BIO_printf(outbio, "Error setting serial number of the certificate\n");
      exit(-1);
  }

  /* Set the new certificate subject name */
  name = X509_NAME_new(); 
  if (name == NULL) 
      exit(-1);
  if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"AK", -1, -1, 0)) 
      exit(-1);
  if (X509_set_subject_name(newcert, name) != 1) {
      BIO_printf(outbio, "Error setting subject name of certificate\n");
      exit(-1);
  }

  /* Set the new certificate issuer name */
  name = X509_NAME_new(); 
  if (name == NULL) 
      exit(-1);
  if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)"safford_ca.com", -1, -1, 0)) 
      exit(-1);   
  if (X509_set_issuer_name(newcert, name) != 1) {
      BIO_printf(outbio, "Error setting issuer name of certificate\n");
      exit(-1);
  }

  /* Set the new certificate public key */
  if (X509_set_pubkey(newcert, req_pubkey) != 1) {
      BIO_printf(outbio, "Error setting public key of certificate\n");
      exit(-1);
  }

  /* Set X509V3 start date (now) and expiration date (+365 days) */
  if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0))) {
      BIO_printf(outbio, "Error setting start time\n");
      exit(-1);
  }

  if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
      BIO_printf(outbio, "Error setting expiration time\n");
      exit(-1);
  }

  /* Add X509V3 extensions */
  X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);

  /* sign new certificate with CA's private key */
  digest = EVP_sha256();
  if (! X509_sign(newcert, ca_privkey, digest)) {
      BIO_printf(outbio, "Error signing the new certificate\n");
      exit(-1);
  }

  /*  output the certificate */
  if (! PEM_write_bio_X509(outbio, newcert)) {
    BIO_printf(outbio, "Error printing the signed certificate\n");
    exit(-1);
   }

  EVP_PKEY_free(req_pubkey);
  EVP_PKEY_free(ca_privkey);
  X509_REQ_free(certreq);
  X509_free(newcert);
  BIO_free_all(reqbio);
  BIO_free_all(outbio);

  exit(0);
}
