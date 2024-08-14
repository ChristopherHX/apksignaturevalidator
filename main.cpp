#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>

#include <openssl/x509.h>
#include <openssl/asn1.h>

#define O_BINARY 0
void printApkSigBlockV2(unsigned const char* c, unsigned const char* end) {
    auto xlen = *(int32_t*)(c);
    c += 4;
    if(xlen != end - c) {
        printf("%x vs %x\n", (int)xlen, (int)(end - c));
    }
    while(c < end) {
        auto signerlen = *(int32_t*)(c);
        c += 4;
        auto signerend = c + signerlen;
        auto signedDatalen = *(int32_t*)(c);
        c += 4;
        auto signedDataend = c + signedDatalen;
        auto alldiglen = *(int32_t*)(c);
        c += 4;
        auto alldigend = c + alldiglen;
        while(c < alldigend) {
            auto diglen = *(int32_t*)(c);
            c += 4;
            auto digid = *(int32_t*)(c);
            c += 4;
            printf("%x:\n", digid);
            auto digplen = *(int32_t*)(c);
            c += 4;
            auto digpend = c + digplen;
            for(; c < digpend; c++) {
                printf("%02X", *c);
            }
            printf("\n");
        }
        auto allcertlen = *(int32_t*)(c);
        c += 4;
        auto allcertend = c + allcertlen;
        while(c < allcertend) {
            auto certlen = *(int32_t*)(c);
            c += 4;
            auto certend = c + certlen;
            auto start = c;
            X509 *cert = d2i_X509(NULL, &start, certlen); // der_len is the length of the DER data

            if(cert == NULL) {
                // Handle error
            }

            // Use the X509 object as needed

            auto serial = X509_get0_serialNumber(cert);

            long int_value = ASN1_INTEGER_get(serial); // Get the long value from ASN1_INTEGER
            printf("ASN1_INTEGER value: %ld\n", int_value); // Print the value
            // serial->
            auto name = X509_get_issuer_name(cert);

                    // Convert the issuer name to a string
            char *issuer_str = X509_NAME_oneline(name, NULL, 0);
            
            if(issuer_str == NULL) {
                // Handle error
                // return -1;
            }

            // Print the issuer name
            printf("Issuer: %s\n", issuer_str);

            name = X509_get_subject_name(cert);

            // Convert the issuer name to a string
            issuer_str = X509_NAME_oneline(name, NULL, 0);
            
            if(issuer_str == NULL) {
                // Handle error
                // return -1;
            }

            // Print the issuer name
            printf("Subject: %s\n", issuer_str);


            // Free the memory
            OPENSSL_free(issuer_str);

            // X509_NAME_get_text_by_OBJ(name, )
            // When done, free the X509 object
            X509_free(cert);


            c = certend;
            // int certout = open("./certout.crt", O_CREAT | O_RDWR | O_BINARY);
            // for(; c < certend; c++) {
            //     printf("%c", *c);
            //     write(certout, c, 1);
            // }
            // printf("\n");
            // close(certout);
        }

        auto alladdattrlen = *(int32_t*)(c);
        c += 4;
        auto alladdattrend = c + alladdattrlen;
        while(c < alladdattrend) {
            auto addattrlen = *(int32_t*)(c);
            c += 4;
            auto addattrid = *(int32_t*)(c);
            c += 4;
            printf("%x:\n", addattrid);
            auto addattrpend = c + addattrlen - 4;
            for(; c < addattrpend; c++) {
                printf("%02X", *c);
            }
            printf("\n");
        }
        c = signedDataend;

        auto allsignatureslen = *(int32_t*)(c);
        c += 4;
        auto allsignaturesend = c + allsignatureslen;
        auto sigbeg = c;
        size_t siglen = 0;
        while(c < allsignaturesend) {
            auto signatureslen = *(int32_t*)(c);
            c += 4;
            auto signaturesid = *(int32_t*)(c);
            c += 4;
            printf("%x:\n", signaturesid);
            auto signaturesplen = *(int32_t*)(c);
            c += 4;
            sigbeg = c;
            auto signaturespend = c + signaturesplen;
            siglen = signaturesplen;
            for(; c < signaturespend; c++) {
                printf("%02X", *c);
            }
            printf("\n");
        }
        c = allsignaturesend;
        auto pubkeylen = *(int32_t*)(c);
        c += 4;
        auto p = c;
        auto pubkey = d2i_PUBKEY(NULL, &p, pubkeylen);

        EVP_PKEY_CTX *ctx;
        const unsigned char *md = sigbeg, *sig = signedDataend - signedDatalen;
        size_t mdlen = siglen;
        EVP_PKEY *verify_key = pubkey;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        if (!EVP_DigestVerifyInit(mdctx, NULL, EVP_get_digestbynid(NID_sha512), NULL, verify_key)) {
            printf("Message digest initialization failed.\n");
            EVP_MD_CTX_free(mdctx);
            exit(1);
        }

        if (!EVP_DigestVerifyUpdate(mdctx, sig, signedDatalen)) {
            printf("Message digest finalization failed.\n");
            EVP_MD_CTX_free(mdctx);
            exit(1);
        }

        if(1 == EVP_DigestVerifyFinal(mdctx, md, siglen))
        {
            /* Success */
            printf("ok\n");
        }
        else
        {
            printf("fail\n");
            /* Failure */
        }

        
        EVP_MD_CTX_free(mdctx);
        
        EVP_PKEY_free(pubkey);
        c = signerend;
    }
}

void printApkSigBlockV3(unsigned const char* c, unsigned const char* end) {
    auto xlen = *(int32_t*)(c);
    c += 4;
    if(xlen != end - c) {
        printf("%x vs %x\n", (int)xlen, (int)(end - c));
    }
    while(c < end) {
        auto signerlen = *(int32_t*)(c);
        c += 4;
        auto signerend = c + signerlen;
        auto signedDatalen = *(int32_t*)(c);
        c += 4;
        auto signedDataend = c + signedDatalen;
        auto alldiglen = *(int32_t*)(c);
        c += 4;
        auto alldigend = c + alldiglen;
        while(c < alldigend) {
            auto diglen = *(int32_t*)(c);
            c += 4;
            auto digid = *(int32_t*)(c);
            c += 4;
            printf("%x:\n", digid);
            auto digplen = *(int32_t*)(c);
            c += 4;
            auto digpend = c + digplen;
            for(; c < digpend; c++) {
                printf("%02X", *c);
            }
            printf("\n");
        }
        auto allcertlen = *(int32_t*)(c);
        c += 4;
        auto allcertend = c + allcertlen;
        while(c < allcertend) {
            auto certlen = *(int32_t*)(c);
            c += 4;
            auto certend = c + certlen;
            auto start = c;
            X509 *cert = d2i_X509(NULL, &start, certlen); // der_len is the length of the DER data

            if(cert == NULL) {
                // Handle error
            }

            // Use the X509 object as needed

            auto serial = X509_get0_serialNumber(cert);

            long int_value = ASN1_INTEGER_get(serial); // Get the long value from ASN1_INTEGER
            printf("ASN1_INTEGER value: %ld\n", int_value); // Print the value
            // serial->
            auto name = X509_get_issuer_name(cert);

                    // Convert the issuer name to a string
            char *issuer_str = X509_NAME_oneline(name, NULL, 0);
            
            if(issuer_str == NULL) {
                // Handle error
                // return -1;
            }

            // Print the issuer name
            printf("Issuer: %s\n", issuer_str);

            name = X509_get_subject_name(cert);

            // Convert the issuer name to a string
            issuer_str = X509_NAME_oneline(name, NULL, 0);
            
            if(issuer_str == NULL) {
                // Handle error
                // return -1;
            }

            // Print the issuer name
            printf("Subject: %s\n", issuer_str);


            // Free the memory
            OPENSSL_free(issuer_str);

            // X509_NAME_get_text_by_OBJ(name, )
            // When done, free the X509 object
            X509_free(cert);


            c = certend;
            // int certout = open("./certout.crt", O_CREAT | O_RDWR | O_BINARY);
            // for(; c < certend; c++) {
            //     printf("%c", *c);
            //     write(certout, c, 1);
            // }
            // printf("\n");
            // close(certout);
        }

        //skip sdk int
        c += 8;

        auto alladdattrlen = *(int32_t*)(c);
        c += 4;
        auto alladdattrend = c + alladdattrlen;
        while(c < alladdattrend) {
            auto addattrlen = *(int32_t*)(c);
            c += 4;
            auto addattrid = *(int32_t*)(c);
            c += 4;
            printf("%x:\n", addattrid);
            auto addattrpend = c + addattrlen - 4;
            for(; c < addattrpend; c++) {
                printf("%02X", *c);
            }
            printf("\n");
        }
        c = signedDataend;

        //skip sdk int
        c += 8;

        auto allsignatureslen = *(int32_t*)(c);
        c += 4;
        auto allsignaturesend = c + allsignatureslen;
        auto sigbeg = c;
        size_t siglen = 0;
        while(c < allsignaturesend) {
            auto signatureslen = *(int32_t*)(c);
            c += 4;
            auto signaturesid = *(int32_t*)(c);
            c += 4;
            printf("%x:\n", signaturesid);
            auto signaturesplen = *(int32_t*)(c);
            c += 4;
            sigbeg = c;
            auto signaturespend = c + signaturesplen;
            siglen = signaturesplen;
            for(; c < signaturespend; c++) {
                printf("%02X", *c);
            }
            printf("\n");
        }
        c = allsignaturesend;
        auto pubkeylen = *(int32_t*)(c);
        c += 4;
        auto p = c;
        auto pubkey = d2i_PUBKEY(NULL, &p, pubkeylen);

        EVP_PKEY_CTX *ctx;
        const unsigned char *md = sigbeg, *sig = signedDataend - signedDatalen;
        size_t mdlen = siglen;
        EVP_PKEY *verify_key = pubkey;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        if (!EVP_DigestVerifyInit(mdctx, NULL, EVP_get_digestbynid(NID_sha512), NULL, verify_key)) {
            printf("Message digest initialization failed.\n");
            EVP_MD_CTX_free(mdctx);
            exit(1);
        }

        if (!EVP_DigestVerifyUpdate(mdctx, sig, signedDatalen)) {
            printf("Message digest finalization failed.\n");
            EVP_MD_CTX_free(mdctx);
            exit(1);
        }

        if(1 == EVP_DigestVerifyFinal(mdctx, md, siglen))
        {
            /* Success */
            printf("ok\n");
        }
        else
        {
            printf("fail\n");
            /* Failure */
        }

        
        EVP_MD_CTX_free(mdctx);
        
        EVP_PKEY_free(pubkey);
        c = signerend;
    }
}

int main(int argc, const char** argv) {
    if(argc != 2) {
        printf("apksignaturevalidator <file.apk>\n");
        return 1;
    }
    int fd = open(argv[1], 0);
    unsigned char sign[(long long)4096 * (long long)64];
    lseek(fd, -sizeof(sign), SEEK_END);
    read(fd, sign, sizeof(sign));
    const char magic[] = "APK Sig Block 42";
    auto res = std::search(std::rbegin(sign), std::rend(sign), std::rbegin(magic) + 1, std::rend(magic));
    if(res != std::rend(sign)) {
        printf("%x\n", (int)(res - std::rbegin(sign)));
        // lseek(fd, -4096 - (std::rend(sign) - res), SEEK_END);
        // read(fd, sign, sizeof(sign));
        
        auto base = res.base();
        auto len = *(uint64_t*)(base - 16 - 8);
        printf("%x(%d)\n", (int)len, (int)len);
        auto start = base - len;
        auto len2 = *(uint64_t*)(start - 8);
        if(len != len2) {
            printf("sig invalid\n");
            return -1;
        }
        for(auto c = start; c < base - 32;) {
            auto l = *(uint64_t*)(c);
            c += 8;
            auto id = *(uint32_t*)(c);
            printf("id: %x\n", (int)id);
            if(id == 0x7109871a) {
                printApkSigBlockV2(c + 4, c + l);
            }
            if(id == 0xf05368c0) {
                printApkSigBlockV3(c + 4, c + l);
            }
            if(id == 0x1b93ad61) {
                printApkSigBlockV3(c + 4, c + l);
            }
            c += l;
        }
    }

    return 0;
}