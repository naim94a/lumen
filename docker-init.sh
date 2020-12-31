#!/bin/sh
CFGPATH="/dockershare"
KEYPATH="/lumen/lumen.p12"
die(){
    echo "Exiting due to error: $@" && exit 1
}
do_config_fixup(){
           sed -i -e "s,connection_info.*,connection_info = \"host=db port=5432 user=lumina password=1\"," \
	   /lumen/config.toml
}
use_default_config(){
    echo "No custom config.toml found, creating secure default."
    tee /lumen/config.toml <<- EOF > /dev/null
	[lumina]
	bind_addr = "0.0.0.0:1234"
	use_tls = true
	server_name = "lumen"
	[lumina.tls]
	server_cert = "${KEYPATH}"
	[database]
	connection_info = "host=db port=5432 user=lumina password=1"
	use_tls = false
	[api_server]
	bind_addr = "0.0.0.0:8082"
	EOF
}
use_default_key(){
    openssl req -x509 -newkey rsa:4096 -keyout /lumen/lumen_key.pem -out /lumen/lumen_crt.pem -days 365 -nodes \
	    --subj "/C=US/ST=Texas/L=Austin/O=Lumina/OU=Naimd/CN=lumen" -passout "pass:" || die "Generating key"
    openssl pkcs12 -export -out /lumen/lumen.p12 -inkey /lumen/lumen_key.pem -in /lumen/lumen_crt.pem  \
	    -passin "pass:" -passout "pass:" || die "Exporting key"
    openssl x509 -in /lumen/lumen_crt.pem -out $CFGPATH/hexrays.crt -passin "pass:" || die "Exporting hexrays.crt"
    echo "hexrays.crt added to mounted volume.  Copy this to your IDA install dir." ;
    sed -i -e "s,server_cert.*,server_cert = \"${KEYPATH}\"," /lumen/config.toml ;
}
setup_tls_key(){
    PRIVKEY=$(find $CFGPATH -type f \( -name '*.p12' -o -name '*.pfx' \) | head -1)
    PASSIN="-passin pass:$PKCSPASSWD"
    if [ ! -z "${PRIVKEY}" ] ; then
        KEYNAME=$(basename "${PRIVKEY}")
	KEYPATH="/lumen/${KEYNAME}"
        echo "Starting lumen with custom TLS certificate ${KEYNAME}" ;
        cp "${PRIVKEY}" $KEYPATH ;
        openssl pkcs12 -in $KEYPATH ${PASSIN} -clcerts -nokeys -out $CFGPATH/hexrays.crt || die "Exporting hexrays.crt from private key. If there's a password, add it in .env as PKCSPASSWD=...";
        echo "hexrays.crt added to mounted volume.  Copy this to your IDA install dir." ;
        sed -i -e "s,server_cert.*,server_cert = \"${KEYPATH}\"," /lumen/config.toml
    else
        echo "No custom TLS key with p12/pfx extension in the custom mount directory." ;
	use_default_key ;
    fi ;
}
setup_config(){
    if [ -e $CFGPATH/config.toml ] ; then
        echo "Detected custom config.toml"
        cp $CFGPATH/config.toml /lumen/config.toml ;
        if grep use_tls /lumen/config.toml | head -1 | grep -q false ; then
            echo "Starting lumen without TLS.  Make sure to set LUMINA_TLS = NO in ida.cfg" ;
        else
	    setup_tls_key ;
        fi ;
    else
	use_default_config ;
	setup_tls_key ;
    fi        
}

setup_config ;
do_config_fixup ;
lumen -c /lumen/config.toml || die "Launching lumen";
