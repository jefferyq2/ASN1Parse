//
//  asn1.c
//  ASN1Parse
//
//  Created by Loren on 2020/4/24.
//  Copyright © 2020 Loren. All rights reserved.
//

#include "asn1.h"
#include <stdlib.h>
#include <string.h>

int asn1_alloc_count = 0;
int asn1_free_count = 0;

void my_free(void *v){
    asn1_free_count++;
    free(v);
}
void * my_malloc(size_t __size){
    asn1_alloc_count++;
    return malloc(__size);
}
void * my_calloc(size_t __count, size_t __size){
    asn1_alloc_count++;
    return calloc(__count, __size);
}

#ifdef DEBUG
#define malloc my_malloc
#define calloc my_calloc
#define free my_free
#endif
struct Node * getNode(struct Node * parentNode){
    struct Node * node = calloc(1, sizeof(struct Node));
    if (parentNode) {
        node->parentNode = parentNode;
        node->cerdata = parentNode->cerdata;
    }
    return node;
}

int parse_data_len(uint8_t * __data,struct ASN1_LEN * len){
    uint8_t * data = __data;
    uint8_t x = *data;
    uint8_t bits = 1;
    size_t size = 0;
    if (x & 0x80) {
        uint8_t b = x&0x7f;
        bits += b;
        if (b>sizeof(size_t)) return -1;//数太大
        for (int i = 0; i<b; i++) {
            *((uint8_t*)&size + i) = *(__data+b-i);
        }
        len->size = size;
        len->bits = bits;
    }
    else{
        len->size = x;
        len->bits = bits;
    }
    return 0;
}

int parseBase128Int(uint8_t * __data,size_t offset,struct ASN1_LEN * __res){
    uint8_t * temp = __data+offset;
    __res->bits = 1;
    __res->size = 0;
    while (1) {
        if (*temp & 0x80) {
            uint8_t x = *temp & 0x7f;
            __res->size = ((__res->size + x) * 128);
        }
        else {
            if (__res->bits == 1) {
                __res->size = *temp;
            }
            else{
                __res->size += *temp;
            }
            if (__res->size >= ((size_t)1 << (sizeof(size_t) * 8 - 1))) {
                return -1;
            }
            break;;
        }
        temp++;
        __res->bits++;
    }
    return 0;
}
int parseObjectIdentifier(uint8_t * __data,size_t __len,struct Node * node,int level){
    struct ASN1_LEN base128;
    if (parseBase128Int(__data,0,&base128) == -1) return -1;
    size_t * decode_data = calloc(__len, sizeof(size_t));
    if (base128.size < 80) {
        decode_data[0] = base128.size/40;
        decode_data[1] = base128.size%40;
    }
    else{
        decode_data[0] = 2;
        decode_data[1] = base128.size - 80;
    }
    size_t offset = 1;
    size_t index = 2;
    while (offset<__len) {
        if (parseBase128Int(__data, offset, &base128) == -1) {free(decode_data); return -1;}
        offset+=base128.bits;
        if (offset>__len) {free(decode_data); return -1;};
        decode_data[index] = base128.size;index ++;
    }
    
    char * temp = calloc(1, 0x10);
    char * ret = calloc(1, node->datalen = 0x100);
    for (int i = 0; i<index; i++) {
        memset(temp, 0, 0x10);
        sprintf(temp, "%ld%s",decode_data[i],i==index-1?"":".");
        strcat(ret, temp);
    }
    free(temp);
    free(decode_data);
    node->data = ret;
    return 0;
}

int parse_integer(uint8_t * __data,size_t __len,struct Node * node,int level){
    if (__len) {
        if (__len>sizeof(size_t)) {//超过了最大值
            char * ret = calloc(1, node->datalen = (__len*2+1));
            char * tempstr = malloc(0x3);
            for (int i = 0; i<__len; i++) {
                memset(tempstr, 0, 0x3);
                sprintf(tempstr, "%02x",__data[i]);
                strcat(ret, tempstr);
            }
            free(tempstr);
            node->data = ret;
        }
        else{
            char * ret = calloc(1, sizeof(size_t)+1);
            size_t bits = __len;
            size_t num = *__data;
            for (int i = 1; i<bits; i++) {
                num<<=8;
                num|=__data[i];
            }
            sprintf(ret, "%zu",num);
            node->data = ret;
        }
    }
    return 0;
}
int parse_bool(uint8_t * __data,size_t __len,struct Node * node,int level){
    return parse_integer(__data,__len,node,level);
}
int parse_bit(uint8_t * __data,size_t __len,struct Node * node,int level){
    if (__len) {
        uint8_t * bitlist = calloc(1, node->datalen=__len);
        node->data = memcpy(bitlist, __data, __len);
    }
    return 0;
}
int parse_utf8_string(uint8_t * __data,size_t __len,struct Node * node,int level){
    return parse_bit(__data,__len,node,level);
}
int parse_bit_string(uint8_t * __data,size_t __len,struct Node * node,int level){
    
    struct Node * childNode = getNode(node);
    if (parse_fdata(__data, __len, childNode, level) != -1) {
        node->childNode = calloc(1, sizeof(struct Node));
        node->childNode[0] = childNode;
        node->childCount = 1;
        return 0;
    }
    free(childNode);
    return parse_bit(__data,__len,node,level);
}
int parse_set(uint8_t * __data,size_t __len,struct Node * node,int level){
    if (__len) {
        struct Node * childNode = getNode(node);
        node->childNode = calloc(1, sizeof(size_t));
        node->childNode[0] = childNode;
        node->childCount = 1;
        return parse_fdata(__data, __len, childNode,level+1);
    }
    return 0;
}
int parse_octet_string(uint8_t * __data,size_t __len,struct Node * node,int level){
    return parse_integer(__data,__len,node,level);
}
int parse_printable_string(uint8_t * __data,size_t __len,struct Node * node,int level){
    return parse_bit(__data,__len,node,level);
}
int parse_utc_time(uint8_t * __data,size_t __len,struct Node * node,int level){
    return parse_bit(__data,__len,node,level);
}
int parse_generalized_time(uint8_t * __data,size_t __len,struct Node * node,int level){
    return parse_bit(__data,__len,node,level);
}
int parse_sequence(uint8_t * __data,size_t __len,struct Node * node,int level){
    
    uint8_t * data = __data;
    int childindex = 0;
    while (data<__data+__len) {
        struct Node * childNode = getNode(node);
        if (parse_fdata(data, __len, childNode,level+1) == -1) return -1;
        if (!node->childNode) {
            node->childNode = calloc(MAXCHILDCOUNT, sizeof(size_t));
        }
        data += childNode->len;
        node->childNode[childindex] = childNode;
        childindex++;
        node->childCount ++;
    }
    return 0;
}
int parse_context_specific(uint8_t * __data,size_t __len,struct Node * node,int level){
    
    struct Node * childNode = getNode(node);
    if (parse_fdata(__data, __len, childNode,level+1) == -1) return -1;
    if (!node->childNode) {
        node->childNode = calloc(1, sizeof(size_t));
    }
    node->childNode[0] = childNode;
    node->childCount = 1;
    
    return 0;
}

int parse_fdata(uint8_t * __data,size_t __len,struct Node * node,int level){
    
    int retcode = -1;
    node->tag = *__data;
    node->len = 0;
    node->offset = (size_t)__data - (size_t)(node->cerdata);
    struct ASN1_LEN asnlen;
    if (parse_data_len(__data+1,&asnlen) == -1) return retcode;
    node->len = asnlen.size + asnlen.bits+1/*tag*/;
    if (node->len>__len) return retcode;
    
    size_t offset = asnlen.bits+1/*tag*/;
    node->dataoffset = node->offset+offset;
    
    switch (node->tag) {
        case 0:
        {
            return parse_fdata(++__data, __len-1, node, level);
        }
            break;
        case ASN1_BOOL:
        {
            node->tagname = "BOOLEAN";
            retcode = parse_bool(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_INTEGER:
        {
            node->tagname = "INTEGER";
            retcode = parse_integer(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_BITSTRING:
        {
            node->tagname = "BIT STRING";
            retcode = parse_bit_string(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_OCTETSTRING:
        {
            node->tagname = "OCTET STRING";
            retcode = parse_octet_string(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_NULL:
        {
            node->tagname = "NULL TAG";
            retcode = 0;
        }
            break;
        case ASN1_ObjectIdentifier:
        {
            node->tagname = "Object Identifier";
            retcode = parseObjectIdentifier(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_UTF8STRING:
        {
            node->tagname = "utf8 string";
            retcode = parse_utf8_string(__data+offset, asnlen.size, node, level);
        }
            break;
        
        case ASN1_PRINTABLESTRING:
        {
            node->tagname = "PRINTABLE STRING";
            retcode = parse_printable_string(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_UTCTIME:
        {
            node->tagname = "UTC TIME";
            retcode = parse_utc_time(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_GENERALIZEDTIME:
        {
            node->tagname = "GENERALIZED TIME";
            retcode = parse_generalized_time(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_SEQUENCE:
        {
            node->tagname = "SEQUENCE";
            retcode = parse_sequence(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_SET:
        {
            node->tagname = "SET";
            retcode = parse_set(__data+offset, asnlen.size, node, level);
        }
            break;
        case ASN1_CONTEXTSPECIFIC:
        case ASN1_CONTEXTSPECIFIC2:
        {
            node->tagname = "parse_context_specific";
            retcode = parse_context_specific(__data+offset, asnlen.size, node, level);
        }
            break;
        default:
        {
            printf("未知 tag %zx\n",node->tag);
            retcode = -1;
        }
            break;
    }
    
    
    return retcode;
}

int parse(char * path,struct Node * node){
    FILE * f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t * fdata = calloc(1, flen);
    fread(fdata, flen, 1, f);
    fclose(f);
    
    memset(node, 0, sizeof(struct Node));
    node->cerdata = fdata;
    int ret = parse_fdata(fdata,flen,node,0);
    free(fdata);
    return ret;
}
//http://oid-info.com/get/1.2.840.113549.1.7.1
const char * get_category_name(char * name){
    if (!name || strlen(name) <=0 ) {
        return "";
    }
    if (!strcmp(name, "1.2.840.113549.1.7.2")) {
        return "signedData";
    }
    if (!strcmp(name, "2.16.840.1.101.3.4.2.1")) {
        return "sha256";
    }
    if (!strcmp(name, "1.2.840.113549.1.7.1")) {
        return "id-data";
    }
    if (!strcmp(name, "1.2.840.113549.1.7.1")) {
        return "sha1-with-rsa-signature";
    }
    if (!strcmp(name, "2.5.4.6")) {
        return "countryName";
    }
    if (!strcmp(name, "2.5.4.8")) {
        return "stateOrProvinceName";
    }
    if (!strcmp(name, "2.5.4.7")) {
        return "localityName";
    }
    if (!strcmp(name, "2.5.4.10")) {
        return "organizationName";
    }
    if (!strcmp(name, "2.5.4.11")) {
        return "organizationalUnitName";
    }
    if (!strcmp(name, "2.5.4.3")) {
        return "commonName";
    }
    if (!strcmp(name, "1.2.840.113549.1.1.1")) {
        return "rsaEncryption";
    }
    if (!strcmp(name, "1.2.840.113549.1.1.5")) {
        return "sha1-with-rsa-signature";
    }
    if (!strcmp(name, "1.3.14.3.2.26")) {
        return "hashAlgorithmIdentifier";
    }
    if (!strcmp(name, "1.2.840.113549.1.9.3")) {
        return "contentType";
    }
    return "";
}

void hex_to_str(uint8_t * hex , size_t len ,char * res){
    char * temp = malloc(3);
    for (int i = 0; i<len; i++) {
        memset(temp, 0, 3);
        sprintf(temp, "%x",hex[i]);
        strcat(res, temp);
    }
    free(temp);
}
void print_node_level(struct Node * node,int level){
    for (int i = 0; i<level; i++) {
        printf(" ");
    }
    
    printf("tag:0x%zx offset:0x%zx len:0x%zx name:%s ",node->tag,node->offset,node->len,node->tagname);
    if (node->data) {
        printf("%s : %s\n",get_category_name(node->data),node->data);
    }
    else{
        printf("\n");
    }
    for (int i = 0; i<node->childCount; i++) {
        struct Node * childNode = node->childNode[i];
        print_node_level(childNode, level+1);
    }

}
void print_node(struct Node * node){
    print_node_level(node,0);
}

void free_node(struct Node * node){
    if (!node) {
        return;
    }
    if (node->data) {
        free(node->data);
    }
    for (int i = 0; i<node->childCount; i++) {
        free_node(node->childNode[i]);
    }
    if (node->childNode) {
        free(node->childNode);
    }
    free(node);
}
