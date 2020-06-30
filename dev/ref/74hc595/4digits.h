/*
 *  This file will show how to drive 4 digits segment displays with 2 cascaded 595 chips
 */

#include "74hc595.h"

#ifndef _4DIGITS_H_
#define _4DIGITS_H_

void set_digits(int num, unsigned char mask);
void set_char(char ch, unsigned char mask);

#endif
