/*
 * cel_verify - verify the event log for a Trusted Business Card (CEL_IMA_TLV)
 *
 * Copyright (C) 2024
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <asm/byteorder.h>
#include <dirent.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>


/* TCG CEL Top Level Field Types */
#define CEL_SEQ 			0
#define CEL_PCR 			1
#define CEL_NVINDEX			2
#define CEL_DIGEST 			3
#define CEL_CONTENT_IMA_TLV		8

/* IMA-TLV Specific Content Types */
#define IMA_TLV_CONTENT_PATH		0
#define IMA_TLV_CONTENT_DATAHASH	1

/* TCG Digest Types from TPM Specification */
#define TPM_ALG_SHA256			11
#define SHA256_HASH_LEN                 32

/* sizes */
#define IMA_PCR		10
#define	NUM_PCRS 	16
#define MAX_DATA_HASH 	32	/* sha-256 */
#define MAX_TLV 	32000   /* dbx variables have gotten BIG */
#define ENTRY_LINE_MAX	2048    /* for RIM file lines */
#define MAX_FNAME	256
#define MAX_HASHES	256     /* max lines in RIM file */

/*  main tlv structure. Note l is in network byte order! */
struct __attribute__ ((__packed__)) tlv {
	uint8_t t;
	uint32_t l;
	uint8_t v[];
};

/* Each CEL record has seq, pcr, digest, and content TLV.
 * During parsing, we save important values for convenience.
 * "type_content" is a pointer to a type specific content structure.
 */
struct record {
	struct tlv *seq;
	struct tlv *pcr;
	struct tlv *digests;
	struct tlv *content;
	uint8_t sha256[SHA256_HASH_LEN];    //from digests
	uint8_t filehash[SHA256_HASH_LEN];  //from content
	char filename[MAX_FNAME];
	int verified_digests;
	int verified_rim;
        void *type_content;
};

struct record_list {
	struct record *record;
	struct record_list *next;
};

struct rim {
	uint8_t sha256[SHA256_HASH_LEN];
	char name[MAX_FNAME];
};

// Globals
int verbose = 0;
struct rim rims[MAX_HASHES];
int have_hashes = 0;

void hexdump(uint8_t *b, int l)
{
	int i;
	for (i=0; i < l; i++)
		printf("%02X",b[i]);
	printf(" ");
}

/* RIM hashfiles are *.HASH, with a 32 byte binary sha256 */
static int read_hashfile(char *dirpath) {
	FILE *f;
	DIR *dir;
        struct dirent *ent;
        char fpath[256];
        int i = 0;

	memset(rims, 'A', sizeof(rims));

        if ((dir = opendir(dirpath)) == NULL) {
                perror("Could not open directory");
                return 0;
        }
        while ((ent = readdir(dir)) != NULL) {
                if(!strstr(ent->d_name, "HASH"))
                        continue;                     
                strcpy(fpath, dirpath);
                strcat(fpath, ent->d_name);
            	f = fopen(fpath, "r");
	        if (!f) 
	              continue;   
                fread(rims[i].sha256, 1, 32, f);
                strcpy(rims[i].name, fpath);
	        fclose(f); 
	        i++;
        }
        
        closedir(dir);
	return 1;
}

int verify_by_rim(uint8_t *h) {
	int i;

	if (!have_hashes)
	        return -1;

	for (i = 0; i < MAX_HASHES; i++) {
	        if (memcmp(rims[i].sha256, h, SHA256_HASH_LEN) == 0)
	                return i;
	}
	return -1;
}

int calculate_sha256(uint8_t *hash, uint8_t *v, int l)
{
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	unsigned int len = 0;

	mdctx = EVP_MD_CTX_new();
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if(!md) {
	        printf("Did not fetch SHA256 ");
	        return -1;
	}
	EVP_DigestInit_ex2(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, v, l);
	EVP_DigestFinal_ex(mdctx, hash, &len);
	EVP_MD_free(md);
	EVP_MD_CTX_free(mdctx);
	return 0;
}

int verify_sha256(uint8_t *hash, uint8_t *v, int l)
{
	uint8_t calculated[SHA256_HASH_LEN];
	int r;

	if ((r = calculate_sha256(calculated, v, l)) != 0)
	        return r;	
	
	return (memcmp(hash, calculated, SHA256_HASH_LEN));
}

static void extend_sha256(uint8_t *pcr, uint8_t *v, int l)
{
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	unsigned int len = 0;

	mdctx = EVP_MD_CTX_new();
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if(!md) {
	        printf("Did not fetch SHA256 ");
	        return;
	}
	EVP_DigestInit_ex2(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, pcr, SHA256_HASH_LEN);
	EVP_DigestUpdate(mdctx, v, l);
	EVP_DigestFinal_ex(mdctx, pcr, &len);
	EVP_MD_free(md);
	EVP_MD_CTX_free(mdctx);
}

static void update_pcrs(struct record *r,
		      uint8_t pcr_sha256[NUM_PCRS][MAX_DATA_HASH])
{
	int pcr;

	pcr = ntohl(*(uint32_t *)(r->pcr->v));
	extend_sha256(pcr_sha256[pcr], r->sha256, SHA256_HASH_LEN);
}


void ascii_dump(uint8_t *b, int l)
{
	int i;
	printf(":");
	for (i=0; i < l; i++) {
		if (b[i] > 31 && b[i] < 127)
			printf("%c",b[i]);
		else
			printf(".");
	}
	printf(" ");
}

static void display_cel_seq(struct tlv *tlv)
{
	uint32_t seq;
	
	seq = ntohl(*(uint32_t *)(tlv->v));
	printf("SEQ %d ", seq);
}

static void display_cel_pcr(struct tlv *tlv)
{
	uint32_t pcr;
	
	pcr = ntohl(*(uint32_t *)(tlv->v));
	printf("PCR %d ", pcr);
}

static void display_digest(struct tlv *tlv)
{
        if(tlv->t == TPM_ALG_SHA256) {
		printf("SHA256 ");
		hexdump(tlv->v, tlv->l);
		printf(" ");
	} else {
		printf("Unknown Digest %02d %02d ",tlv->t, tlv->l);
		hexdump(tlv->v, tlv->l);
	}
}

static void display_cel_digest(struct tlv *tlv)
{
	struct tlv *tmp;
	int pos;

	printf("DIGESTS ");
	/* Walk through the one or more nested digest tlv's.
	 * Lengths in the nested TLV's were fixed in read.
	 */
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);		
		display_digest(tmp);
		pos += tmp->l + 5;
	}
}

static void display_ima_tlv_content(struct tlv *tlv) {

	char filename[128];
	memset(filename, 0, 128);
	
	// t l [t l [filename] t l [hash]]
        printf("CEL_CONTENT_IMA_TLV ");
        memcpy(filename, (tlv->v) + 5, tlv->l - 42);
        printf("\n    Filename %s \n    Filehash: ", filename);
        hexdump(tlv->v + tlv->l - 32, 32);
        printf("\n");
}

static void display_cel_content(struct record *r)
{
	switch (r->content->t) {			
		case CEL_CONTENT_IMA_TLV :
			display_ima_tlv_content(r->content);
			break;	
		default :
			printf("This program only supports CEL_IMA_TLV contenttype %d ", r->content->t);
	}
}

static void display_record(struct record *r)
{
	display_cel_seq(r->seq);
	display_cel_pcr(r->pcr);
	if (verbose)
	        display_cel_digest(r->digests);
	display_cel_content(r);
	if (r->verified_digests)
	        printf("    Entire Content TLV Verified by digest\n");
	if (r->verified_rim > 0)
	        printf("    File Hash Verified by signed RIM \n");
	printf("\n");
}

/* Allocate and read in a TLV from stdin
 * CEL is network byte order, so be sure to fix length endianness of all top level tlvs.
 */
static struct tlv *read_cel_tlv(void)
{
	uint8_t t = 0;
	uint32_t l = 0;
	struct tlv *tlv;
	
	if (read(0, (void *)&(t), 1) != 1)
		return NULL;
	if (read(0, (void *)&(l), 4) != 4)
		return NULL;
	l = ntohl(l);
	if (l > (MAX_TLV - 5)){
		printf("Invalid TLV length: %08X ", l);
		return NULL;
	}	
	tlv = (struct tlv *)malloc(l+5);
	if (!tlv) {
		printf("Malloc failed while reading event ");
		return NULL;
	}
	tlv->t = t;
	tlv->l = l;
	if (read(0, (void *)(tlv->v), l) != l){
		free(tlv);
		return NULL;
	}
	return tlv;
}
	
/* Walk through the one or more nested digest tlv's.
 * Lengths in the nested TLV's must be fixed.
 */
static void fix_digest(struct record *r) {
	struct tlv *t, *tmp;
	int pos;

	t = r->digests;

	for (pos=0; pos + 5 < t->l; ) {
		tmp = (struct tlv *)((unsigned char *)t + pos + 5);
		tmp->l = ntohl(tmp->l);	
		if (tmp->t == TPM_ALG_SHA256) {
		        memcpy(r->sha256, tmp->v, SHA256_HASH_LEN);
		}
		pos += tmp->l + 5;
	}
}

/* get the filename and filehash out of the IMA_TLV Content, and verify */
static void parse_ima_tlv_content(struct record *r){
        uint8_t *fn, *fh;
        int fnlen;
        uint32_t l;
        
        // t l [ t l [filename] t l [filehash] ]
        // The conteent l has already been fixed, Have to fix sub tlv lengths.
        fnlen = ntohl(*(uint32_t *)(r->content->v + 1));
        fn = (r->content->v + 5);
        fh = (r->content->v + 10 + fnlen);
        
        memcpy(r->filename, fn, fnlen);
        memcpy(r->filehash, fh, 32);

        // first verify that content matches digest hash  
        // have to revert top level length before hashing the content!
        l = r->content->l;
        r->content->l = htonl(l);
        r->verified_digests = !verify_sha256(r->sha256, (uint8_t *)r->content, l + 5);
        r->content->l = l;

        // verify filehash by rim
         if(verify_by_rim(fh) != -1)
                r->verified_rim = 1;
         else
                r->verified_rim = 0;
}

/* Read and return one record (four top level tlv). */
static struct record *read_record(void)
{
	struct record *record;
	
	record = (struct record *) malloc(sizeof(struct record));
	if (!record)
		return NULL;
	record->seq = read_cel_tlv();
	if (!record->seq || record->seq->t != CEL_SEQ)
		return NULL;
	record->pcr = read_cel_tlv();
	if (!record->pcr || record->pcr->t != CEL_PCR)
		return NULL;
	record->digests = read_cel_tlv();
	if (!record->digests || record->digests->t != CEL_DIGEST)
		return NULL;
	fix_digest(record);
	record->content = read_cel_tlv();
	if(!record->content)
		return NULL;
	if (record->content->t == CEL_CONTENT_IMA_TLV)
	        parse_ima_tlv_content(record);
	        
	return record;
}

/* read an entire event log from stdin, and return the head record */
static struct record_list * read_list(void)
{
	struct record *r;
	struct record_list *head = NULL, *current = NULL, *new;
	
	while ((r = read_record())){
		new = (struct record_list *)malloc(sizeof(struct record_list));
		new->record = r;
		new->next = NULL;
		if (!head)
			head = new;
		else
			current->next = new;
		current = new;	
	}	
			
	return head;
}

/*
 * cel_verify - verify a CEL-TLV formatted event log
 *              cel_verify [-p pcrbinfile][-h hashfile][-v]
 *              reads from stdin, sends to stdout
 *              pcrbinfile is file from which to read target pcrs in binary form.
 *              Create this with "tpm2_pcrread -o <path> sha256"
 *              hashbinfile is ascii lines with ascii-hex sha256 hash followed by text description.
 */
int main(int argc, char *argv[])
{
	static uint8_t pcr_sha256[NUM_PCRS][MAX_DATA_HASH];
	static uint8_t pcr10[SHA256_HASH_LEN];
	struct record_list *head, *rl;
	int c, pcr, fd, have_pcrs = 0, pcr10_matched = 0;
	size_t s;
	char *pcrbinfile = NULL;
	char *hashfile = NULL;
	
	while ((c = getopt(argc, argv, "p:h:v")) != -1) {
	        switch (c) {
	                case 'p':
	                        pcrbinfile = optarg;
	                break;
	                case 'h':
	                        hashfile = optarg;
	                break;
	                case 'v':
	                        verbose = 1;
	        }
	}
	
	/* If sha256 target pcr values are available, read them in */
	if (pcrbinfile) {
	        fd = open(pcrbinfile, O_RDONLY);
	        if (fd != -1) {
	                s = read(fd, (void *)pcr10, sizeof(pcr10));
	                if (s == sizeof(pcr10))
	                        have_pcrs = 1;
	        }
	}
	
	if (hashfile)
	        have_hashes = read_hashfile(hashfile);
	        
	/* read in the whole event log as records of tlvs */
	head = read_list();

	/* calculate the effective pcr values from the log */
	for (rl = head; rl != NULL; rl = rl->next) {
		update_pcrs(rl->record, pcr_sha256);
		pcr = ntohl(*(uint32_t *)(rl->record->pcr->v));
		if ((pcr == 10) && have_pcrs &&
		        memcmp(pcr_sha256[10], pcr10, SHA256_HASH_LEN) == 0)
		                pcr10_matched = 1;
	}
		
	/* check and display calculated PCR values */
	printf("\nVerifying Event Log Against PCRs\n\n");
	for (pcr = 0; pcr < NUM_PCRS; pcr++) {
		printf("PCR %02d SHA256: ", pcr);
		hexdump(pcr_sha256[pcr], SHA256_HASH_LEN);
		if (have_pcrs && (pcr == 10)) {
		        if (memcmp(pcr_sha256[pcr], pcr10, SHA256_HASH_LEN) == 0)
		                printf(" MATCHES");
		        else {
		                if ((pcr == 10) && pcr10_matched)
		                        printf(" MATCHED EARLIER");
		                else {
		                        printf(" NO MATCH \n    looking for ");
		                        hexdump(pcr10, SHA256_HASH_LEN);
		                }
		                        
		        }
		}
		printf("\n");
	}
	
	/* walk the list and display records */	
	if (verbose)
	        printf("\nDumping all event records\n\n");
	else
	        printf("\nSummarizing all events\n\n");

	for (rl = head; rl != NULL; rl = rl->next)
		display_record(rl->record);	
}
