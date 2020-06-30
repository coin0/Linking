#include "4digits.h"

void cs();
int send_byte();

// display digits ----------- 0  ,  1  ,  2  ,  3  ,  4  ,  5  ,  6  ,  7  ,  8  ,  9
unsigned char digit_out[] = {0xc0, 0xf9, 0xa4, 0xb0, 0x99, 0x92, 0x82, 0xf8, 0x80, 0x90};
unsigned char dot_out = 0x7f;

// select bit position to display from right to left
unsigned char bit_select[] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

// delay - ms
int clk_delay = 10000;

void delay_ms(int delay)
{
	for (int i = 0; i < delay; i++);
}

void cs()
{
	hc595_stcp_low();
	delay_ms(clk_delay);
	hc595_stcp_high();
	delay_ms(clk_delay);
}

void send_data(unsigned char seg, unsigned char bit)
{
	int input = (seg << 8) + bit;

	int bit_count = 0;
	for (; bit_count < 16; bit_count++) {

		// send bit 0 or 1
		if (input & 0x8000) {
			hc595_data_high(); // bit:1
		} else {
			hc595_data_low();  // bit:0
		}

		// send to shifting register
		hc595_shcp_low();
		delay_ms(clk_delay);
		hc595_shcp_high();
		delay_ms(clk_delay);

		// next bit
		input <<= 1;
	}

	cs();
}

void set_digits(int num, unsigned char mask)
{
	unsigned int dot_mask;

	// display segment digits from right to left
	for (int bit_pos = 7; bit_pos > 0; bit_pos--) {
		if (mask & 0x0001)
			dot_mask = dot_out; // display dot
		else
			dot_mask = 0xff;    // hide dot
		mask >>= 1;

		// display current low decimal digit by MOD function
		send_data(digit_out[num % 10] & dot_mask, bit_select[bit_pos]);
		num /= 10; // next digit
	}
}

void set_char(char ch, unsigned char mask)
{

}
