//
//  main.m
//  ASN1Parse
//
//  Created by Loren on 2020/4/23.
//  Copyright © 2020 Loren. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "asn1.h"

#define asn1_file1 "/Users/loren/Desktop/ASN1Parse/ASN1Parse/RSA/asn1.RSA"
#define asn1_file2 "/Users/loren/Desktop/ASN1Parse/ASN1Parse/RSA/asn2.RSA"

#define path(a)
//Windows可视化工具https://github.com/jiftle/Asn1Editor
//参考https://github.com/liwugang/pkcs7
int main(int argc, const char * argv[]) {
    
    {
        char * path = asn1_file1;
        struct Node * node = calloc(1, sizeof(struct Node));
        parse(path, node);
        print_node(node);
        free_node(node);
    }
    {
        char * path = asn1_file2;
        struct Node * node = calloc(1, sizeof(struct Node));
        parse(path, node);
        print_node(node);
        free_node(node);
    }
    return 0;
}
