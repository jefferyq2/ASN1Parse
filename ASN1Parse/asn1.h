//
//  asn1.h
//  ASN1Parse
//
//  Created by Loren on 2020/4/24.
//  Copyright © 2020 Loren. All rights reserved.
//

#ifndef asn1_h
#define asn1_h

#include <stdio.h>

#define MAXCHILDCOUNT 10

typedef enum : int {
    ASN1_BOOL = 0x1, //bool类型
    ASN1_INTEGER = 0x2, //整数类型
    ASN1_BITSTRING = 0x3,//位字符串
    ASN1_OCTETSTRING = 0x4,//字节字符串
    ASN1_NULL = 0x5,//null
    ASN1_ObjectIdentifier = 0x06,//Base128Int 数组
    ASN1_UTF8STRING = 0xc, // utf8 str
    ASN1_PRINTABLESTRING = 0x13,//printable string
    ASN1_UTCTIME = 0x17,//utc time 120606023315Z
    ASN1_GENERALIZEDTIME = 0x18, //generalized time 20670310023315Z
    ASN1_SEQUENCE = 0x30,//struct 或者 字典
    ASN1_SET = 0x31,//集合
    ASN1_CONTEXTSPECIFIC = 0xA0,
    ASN1_CONTEXTSPECIFIC2 = 0xA3,

} ASN1TAG;

struct ASN1_LEN {
    size_t size;//长度
    size_t bits;//位数
};
typedef enum : int {
    FOPENERROR,
    FILEERROR,
} ASN1ERROR;

struct Node {
    size_t tag;
    size_t offset;
    size_t len;
    size_t dataoffset;
    
    void * data;
    size_t datalen;
    
    int childCount;
    struct Node * * childNode;
    struct Node * parentNode;
    
    const char * tagname;
    void * cerdata;
};

int parse(char * path,struct Node * node);

void print_node(struct Node * node);
void free_node(struct Node * node);

int parse_fdata(uint8_t * __data,size_t __len,struct Node * node,int level);
int parse_data_len(uint8_t * __data,struct ASN1_LEN *len);
#endif /* asn1_h */
