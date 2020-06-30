#ifndef _ESP8266_H_
#define _ESP8266_H_

// --------------------------------------dependency----------------------------------------

#include "main.h"
#include "string.h"
#include "stdio.h"

extern UART_HandleTypeDef huart3;
#define huart_wifi huart3

#define uart_send(buf, size, timeout) HAL_UART_Transmit(&huart_wifi, buf, size, timeout)
#define uart_recv(buf, size, timeout) HAL_UART_Receive(&huart_wifi, buf, size, timeout)

#define uart_send_dma(buf, size)      HAL_UART_Transmit_DMA(&huart_wifi, buf, size)
#define uart_recv_dma(buf, size)      HAL_UART_Receive_DMA(&huart_wifi, buf, size)

#define delay_ms HAL_Delay

// ------------------------------------------------------------------------------------------

#endif
