#!/bin/bash
#############################################################################
#  
# Generate platform certs and provision a Trusted Business Card
#
#    1. read ak.der, ek.der, and ek.crt
#    2. verify that ek.der matches pub key in ek.crt
#    3. verify ek.crt chain
#    4. get card serial number from command arg[1]
#    5. use paccor to create platform.crt and save
#    6. use certgen.c to sign ak.der as ak.crt, and save
#    7. create and sign RIM (file hashes) and save
#    8. save random atchal.bin
#
###########################################################################

# args: card number card_path (e.g. /dev/sdc1)
if [ $# -ne 2 ]; then
    echo "Usage tbc_certify.sh card_number card_path"
    exit
fi
card_ser=$1
card_path=$2

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
card_dir=`df | grep $card_path | awk '{print $6}'`"/ESP/"

# Card Files in
ekcert="EK.CRT"
akder="AK.DER"
ekder="EK.DER"

# card files out
pccert="PLATFORM.CRT"
akcert="AK.CRT"

# keys
sigkey=$key_dir"private.pem"
pubkey=$key_dir"public.pem"
pcsigncert=$cert_dir"safford_ca.com.pem"

### Certificate params
extsettings=$json_dir"extentions.json"
componentlist=$json_dir"localhost-componentlist.json"
component_template=$json_dir"localhost-componentlist_template.json"
policyreference=$json_dir"localhost-policyreference.json"
serialnumber="0001"
dateNotBefore="20180101"
dateNotAfter="20280101"
card_ser_txt="s/XXCARD_SERXX/""$card_ser""/"

### Key Pair params
# make sure DN exactly matches what certgen uses!!!
subjectDN="/O=safford_ca.com"
daysValid="3652"
sigalg="rsa:2048"

# copy all the input files from the card
cp $card_dir$ekcert .
cp $card_dir$ekder .
cp $card_dir$akder  .

# First check that EK.DER matches EK.CRT
# Since we know that EK.DER was created on this TPM,
# (we just flashed the reading program on the card),
# if the public key matches the EK.CRT, we know that
# we are talking to the TPM that matches the ek cert.
# This saves having to do the make/activate credential thing.

# First pull public key from EK CERT
openssl x509 -pubkey -noout -in EK.CRT -out EK_from_crt.PEM
openssl pkey -in EK_from_crt.PEM  -pubin -outform der -out EK2.DER
# compare it to EK.DER from card
if cmp -s EK.DER EK2.DER; then
	echo EK created on card matches EK from Infineon Certificate
else
	echo EK created on card does not match EK from Infineon Certificate
fi

# If needed, create a sample signing key pair
if ! [ -e "$pcsigncert" ]; then
    echo "Creating a signing key for signing platform credentials"
    $(openssl req -x509 -nodes -days "$daysValid" -newkey "$sigalg" -keyout "$sigkey" -out "$pcsigncert" -subj "$subjectDN" >> /dev/null)
    if [ $? -ne 0 ]; then
        echo "Failed to create the key pair, exiting"
        exit 1
    fi
    openssl x509 -pubkey -noout -in $pcsigncert -outform pem -out $pubkey
else 
    echo "Platform Signing file exists, skipping"
fi

# set serial number in localhost json file
sed $card_ser_txt $component_template > $componentlist

# check for JSON errors
printf "Checking JSON files"
if ! cat "$componentlist" | jq -e . >/dev/null; then
    echo "Component file has JSON errors, exiting"
    exit 1
fi

if ! cat "$policyreference" | jq -e . >/dev/null; then
    echo "Policy settings file has JSON errors, exiting"
    exit 1
fi

if ! cat "$extsettings" | jq -e . >/dev/null; then
    echo "Extensions file has JSON errors, exiting"
    exit 1
fi
printf "...OK\n"

# check for signing keys
if ! [ -e "$pcsigncert" ]; then
	echo "Failed to create the key pair, exiting"
        exit 1
else 
    echo "Platform Signing file ok "
fi

# create and sign the new platform cert
echo "Generating a signed Platform Cert"
rm -f $pccert
bash $signer_bin -x $extsettings -c $componentlist -e $ekcert -p $policyreference -k $sigkey -P $pcsigncert -N $serialnumber -b $dateNotBefore -a $dateNotAfter -f $pccert
if ! [ -e "$pccert" ]; then
    echo "The signer could not produce a Platform Credential, exiting"
    exit 1
fi

# validate the signature
echo "Validating the signature"
bash $validator_bin -P "$pcsigncert" -X "$pccert"

if [ $? -eq 0 ]; then
    echo "PC Credential Creation Complete."
    echo "Platform Credential has been placed in ""$pccert"
else
    # rm -f "$pccert"
    echo "Error with signature validation of the credential."
fi

# create ak certificate
openssl rsa -pubin -inform=der -in AK.DER -outform pem -out AK.PEM
$certgen_bin > AK_CERT.PEM
openssl x509 -inform pem -in AK_CERT.PEM -outform der -out AK.CRT

# create rim from files in file_dir
for F in `ls ./files`; do
    echo $F
    openssl dgst -sha256 -sign ./keys/private.pem -out $rim_dir$F".SIG" "./files/"$F
    openssl dgst -sha256 -binary -out $rim_dir$F".HASH" "./files/"$F
done

# copy files to card
cp $pccert $card_dir
cp $akcert $card_dir
cp $file_dir* $card_dir

# save files from card
ekcertsave="$out_dir""card_""$card_ser""_""$ekcert"
cp $ekcert $ekcertsave
pcsave="$out_dir""card_""$card_ser""_""$pccert"
cp $pccert $pcsave
aksave="$out_dir""card_""$card_ser""_""$akcert"
cp $akcert $aksave
eksave="$out_dir""card_""$card_ser""_""$ekder"
cp $ekder $eksave

#cleanup
rm -f AK.CRT AK.DER AK.PEM AK_CERT.PEM EK.CRT PLATFORM.CRT EK_from_crt.PEM EK2.DER
