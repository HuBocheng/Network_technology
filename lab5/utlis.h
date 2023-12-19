#pragma once
#include <iostream>
#include <stdio.h>
#include "package.h"

void outputIp(uint32_t IP);
bool cmp(uint8_t A[], uint8_t B[]);
void setChecksum(ICMP *tmp);
bool check(ICMP *tmp);

void setChecksum(ICMPTimeExceededResponse *response);
bool check(ICMPTimeExceededResponse *response);

void setChecksum(IP_header *response);
bool check(IP_header *response);

void printinfo(ICMP *tmp);
void printinfo(ICMPTimeExceededResponse *response);
