#!/bin/bash
#############################################################################
#  
# Generate platform certs for Trusted Business Card
#
# Verify a card:
#    1. read ek.crt, ak.crt, and platform.crt and verify against CAs
#    2. read quote and verify against ak.crt
#    3. read log and verify against pcr-10 and RIM for all files.
#
###########################################################################

#  HIRS can also be used as a GUI verification tool. 
#  Install it with:
#     podman run --name=aca -p 8443:8443 ghcr.io/nsacyber/hirs/aca:latest
#  Then stop/start/delete it with:
#     podman stop aca
#     podman start aca
#     podman rmi -f aca
#  Point your browser to localhost:8443 

#### paccor binaries
tool_path="/opt/paccor/bin"
signer_bin="$tool_path""/signer"
validator_bin="$tool_path""/validator"
certgen_bin="./tools/certgen"

# directories
cert_dir="./certs/"
key_dir="./keys/"
file_dir="./files/"
out_dir="./out/"
json_dir="./json/"
rim_dir="./rim/"
card_dir=`find /run/media -name ESP -print 2> /dev/null`"/" 

# Card Files
ekcert="EK.CRT"
akder="AK.DER"
ekder="EK.DER"
pccert="PLATFORM.CRT"
akcert="AK.CRT"
log="LOG.BIN"
pcrs="PCR.BIN"
chall="CHALL.BIN"
quotedat="QUOTE.DAT"
quotesig="QUOTE.SIG"

# keys
pubkey=$key_dir"public.pem"
pcsigncert=$cert_dir"safford_ca.com.pem"

echo Verification Report for Trusted Business Card at $card_path
echo

# verify ek cert - verification also works in HIRS
echo Verifying Endorsement Key Certificate from Infineon
openssl x509 -in $card_dir$ekcert -text -noout
echo
echo -n EK.CRT verification:
openssl verify -CAfile certs/OptigaRsaRootCA2.crt -untrusted certs/OptigaRsaMfrCA065.crt $card_dir$ekcert
echo

# verify that EK.DER matches EK.CRT
echo Verifying that the Card\'s EK.DER matches the EK certificate
openssl x509 -pubkey -noout -in $card_dir$ekcert -out EK_from_crt.PEM 
openssl pkey -in EK_from_crt.PEM  -pubin -outform der -out EK2.DER
# compare it to EK.DER from card
if cmp -s $card_dir$ekder EK2.DER; then
	echo EK created on card matches EK from Infineon Certificate
else
	echo EK created on card does not match EK from Infineon Certificate
fi
rm -f EK_from_crt.PEM EK2.DER
echo

# verify ak cert - verification also works in HIRS
echo Verifying Attestation Key Certificate from Dave
openssl x509 -in $card_dir$akcert -text -noout
echo -n AK.CRT verification: 
openssl verify -CAfile certs/safford_ca.com.pem $card_dir$akcert
echo

# verify that AK.DER matches AK.CRT
echo Verifying that the Card\'s AK.DER matches the AK certificate
openssl x509 -pubkey -noout -in $card_dir$akcert -out AK_from_crt.PEM 
openssl pkey -in AK_from_crt.PEM  -pubin -outform der -out AK2.DER
# compare it to EK.DER from card
if cmp -s $card_dir$akder AK2.DER; then
	echo AK created on card matches AK from AK Certificate
else
	echo AK created on card does not match AK Certificate
fi
rm -f AK_from_crt.PEM AK2.DER
echo

# verify platform cert
echo "Validating the platform key signature with Paccor"
bash $validator_bin -P "$pcsigncert" -X $card_dir$pccert
if [ $? -eq 0 ]; then
    echo "Platform Certificate Validated."
else
    echo "Error with signature validation of the credential."
fi
echo

# verify quote: 
# OK, wolfTPM returns the raw TPM data structures, so tpm2_checkquote
# will NOT WORK. We have to manually walk the chain from PCR.BIN to QUOTE.SIG
# PCR.BIN --sha256--> QUOTE.DAT --sha256--> decrypt.bin <--AK.PUB-- QUOTE.SIG
#
# Decrypt sig with AK.DER, last 32 should be sha256 of QUOTE.DAT
# The last 32 bytes of QUOTE.DAT should be the sha256 of PCR.BIN
echo Verifying TPM_QUOTE
echo
echo Decrypting quote with AK
openssl rsautl -verify -inkey $card_dir$akder -pubin -in $card_dir$quotesig -out decrypt.bin >& /dev/null
echo Decrypted data:
hexdump -C decrypt.bin

openssl dgst -sha256 -binary -out dathash.bin $card_dir$quotedat
echo sha256 of QUOTE.DAT
hexdump -C dathash.bin
echo
echo QUOTE.DAT
hexdump -C $card_dir$quotedat

echo
openssl dgst -sha256 -binary -out pcrhash.bin $card_dir$pcrs
echo hashed PCR.BIN
hexdump -C pcrhash.bin
echo

echo PCR.BIN
hexdump -C $card_dir$pcrs
echo
# check that pcrhash.bin is last 32 of QUOTE.DAT
# Dump last 32 of QUOTE.DAT and compare to pcrhash.bin
tail -c 32 $card_dir$quotedat  > quote32.bin
if cmp -s pcrhash.bin quote32.bin; then
	echo Quoted data matches pcr10 data
else
	echo Quoted data does not match pcr10 data
fi
echo

# check that dathash.bin is last 32 of decrypt.bin
# Dump last 32 of decrypt.bin and compare to datahash.bin
tail -c 32 decrypt.bin > decrypt32.bin
if cmp -s dathash.bin decrypt32.bin; then
	echo Hash of quoted data matches decrypted signature
else
	echo Hash of quoted data does not match decrypted signature
fi
echo

#verify RIM signatures
for F in `ls ./files`; do
    echo verifying rim for $F
    openssl pkeyutl -in $rim_dir$F.HASH -inkey ./keys/public.pem -pubin -verify -sigfile $rim_dir$F.SIG -pkeyopt digest:sha256
done

# verify log with cel_utils and RIM
cp $card_dir$pcrs .
cp $card_dir$log .
cat LOG.BIN | tools/cel_verify -h ./rim/ -p PCR.BIN

# make sure that card was using correct challenge file
echo Checking that current challenge file was used.
if cmp -s $card_dir$chall $chall; then
	echo Correct challenge file was used.
else
	echo Incorrect Challenge was reported
fi

# save a new random challange file to card
echo Writing a new random challenge. Reset the card for it to be measured.
dd if=/dev/random count=1 of=$chall >& /dev/null
cp $chall $card_dir

#cleanup
rm -f LOG.BIN PCR.BIN decrypt.bin dathash.bin pcrhash.bin quote32.bin decrypt32.bin

# If you want to verify the factory (application) partition on the card: 
# cd to your esp-idf partition
# . export.sh
# parttool.py -p /dev/ttyACM0 read_partition --partition-name=factory --output=factory.bin
# openssl dgst -sha256 -hex factory.bin
# The output should be
# SHA2-256(factory.bin)= 67b79b8905359fd462f8a42e645c0730728b5c51c648f1b1a1b49734d5b74b55

