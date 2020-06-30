#include "trans.h"

#define UART_RX_BUF_SIZE 200
#define UART_TX_BUF_SIZE 1024
typedef struct {
	uint8_t rxbuf[UART_RX_BUF_SIZE];
	uint16_t rxlen;
	uint8_t rxflag;
	uint8_t txbuf[UART_TX_BUF_SIZE];
	uint16_t txlen;
	uint8_t txflag;
} uart_buf_t;

int rxbuf_expect_str(uart_buf_t* buf, const char* pattern);

int cmd_timeout = 0xffff;
uart_buf_t uart_buf;

int wifi_send_command(const char* cmd, const char* expect_resp, int delay)
{
	size_t len = strlen(cmd);
	if (len > UART_TX_BUF_SIZE) return -1;

	memset(uart_buf.rxbuf, 0, UART_RX_BUF_SIZE);
	memset(uart_buf.txbuf, 0, UART_TX_BUF_SIZE);
	memcpy(uart_buf.txbuf, cmd, len);

	uart_send_dma((uint8_t*)uart_buf.txbuf, (uint16_t)len);
	delay_ms(delay);

	return rxbuf_expect_str(&uart_buf, expect_resp);
}

int wifi_connect_ap(const char* ssid, const char* psw)
{
	int err = 0;

	for (int retry = 1; retry > 0; retry--) {
		// AT+RST - reset esp8266
		char* rst = "AT+RST\r\n";
		uart_send_dma((uint8_t*)rst, (uint16_t)strlen(rst));
		delay_ms(2000);

		// AT - check if MCU is ok
		if (wifi_send_command("AT\r\n", "OK", 100) != 0) {
			err = 1;
			continue;
		}

		// AT+CWMODE_CUR=1 - set station mode
		if (wifi_send_command("AT+CWMODE_CUR=1\r\n", "OK", 100) != 0) {
			err = 2;
			continue;
		}

		// AT+CWJAP_CUR=%ssid%,%psw% - connect AP
		char conn_ap[128] = {0};
		sprintf(conn_ap, "AT+CWJAP_CUR=\"%s\",\"%s\"\r\n", ssid, psw);
		if (wifi_send_command(conn_ap, "OK", 8000) != 0) {
			err = 3;
			continue;
		}

		return 0;
	}

	return err;
}

int wifi_tcp_connect(const char* host, int port)
{
	int err = 0;

	for (int retry = 1; retry > 0; retry--) {
		// AT+CIPSTART=TCP,%HOST_IP%,%PORT% - establish TCP connection to the host
		char conn_tcp[512] = {0};
		if (strlen(host) > 512) return 1; // no retry attempt
		sprintf(conn_tcp, "AT+CIPSTART=\"%s\",\"%s\",%d\r\n", "TCP", host, port);
		if (wifi_send_command(conn_tcp, "CONNECT", 4000) != 0) {
			err = 2;
			continue;
		}

		// AT+CIPMODE=1 - transparent mode
		if (wifi_send_command("AT+CIPMODE=1\r\n", "OK", 100) != 0) {
			err = 3;
			continue;
		}

		// AT+CIPSEND - ready to send data
		if (wifi_send_command("AT+CIPSEND\r\n", ">", 100) != 0) {
			err = 4;
			continue;
		}

		return 0;
	}

	return err;
}

int wifi_tcp_send(const char* wbuf, int size)
{
	return 0;
}

int wifi_tcp_receive(char* rbuf, int size)
{
	return 0;
}

void usart_receive_idle(UART_HandleTypeDef *huart)
{
    uint32_t size;

    if((__HAL_UART_GET_FLAG(huart, UART_FLAG_IDLE) != RESET))
    {
        __HAL_UART_CLEAR_IDLEFLAG(&huart_wifi);
        size = huart_wifi.Instance->SR;
        size = huart_wifi.Instance->DR;
        HAL_UART_DMAStop(&huart_wifi);
        size = huart_wifi.hdmarx->Instance->CNDTR;
        uart_buf.rxlen = UART_RX_BUF_SIZE - size;
        uart_buf.rxflag = 1;
        uart_recv_dma(uart_buf.rxbuf, UART_RX_BUF_SIZE);
    }
}

void usart_enable_it()
{
  __HAL_UART_ENABLE_IT(&huart_wifi, UART_IT_IDLE);
  uart_recv_dma(uart_buf.rxbuf, UART_RX_BUF_SIZE);
}

// TODO: KMP
int rxbuf_expect_str(uart_buf_t* buf, const char* pattern)
{
	int i, j, bingo = 0;
	const uint8_t* p = (uint8_t*)pattern;

	for (i = 0; i < UART_RX_BUF_SIZE; i++) {
		for (bingo = 0, j = i; j < UART_RX_BUF_SIZE;) {
			if (buf->rxbuf[j] == p[bingo]) {
				bingo++; j++;
				if (p[bingo] == 0) return 0; // it's \0, end of pattern
			} else {
				break;
			}
		}
	}

	return 1;
}
