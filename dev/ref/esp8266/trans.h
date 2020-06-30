#ifndef _TRANS_H_
#define _TRANS_H_

#include "esp8266.h"

int wifi_connect_ap(const char* ssid, const char* psw);
int wifi_tcp_connect(const char* host, int port);
int wifi_tcp_send(const char* wbuf, int size);
int wifi_tcp_receive(char* rbuf, int size);

void usart_receive_idle(UART_HandleTypeDef *huart);
void usart_enable_it();

#endif
