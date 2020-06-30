#ifndef _74HC595_H_
#define _74HC595_H_

// --------------------------------------dependency----------------------------------------

#include "main.h"

/* PIN 14 */
#define PORT_DS DS_GPIO_Port
#define PIN_DS DS_Pin

/* PIN 11 */
#define PORT_SHCP SHCP_GPIO_Port
#define PIN_SHCP SHCP_Pin

/* PIN 12 */
#define PORT_STCP STCP_GPIO_Port
#define PIN_STCP STCP_Pin

// ------------------------------------------------------------------------------------------

#define hc595_data_low()   HAL_GPIO_WritePin(PORT_DS,PIN_DS, GPIO_PIN_RESET)
#define hc595_data_high()  HAL_GPIO_WritePin(PORT_DS,PIN_DS, GPIO_PIN_SET)
#define hc595_shcp_low()   HAL_GPIO_WritePin(PORT_SHCP, PIN_SHCP, GPIO_PIN_RESET)
#define hc595_shcp_high()  HAL_GPIO_WritePin(PORT_SHCP, PIN_SHCP, GPIO_PIN_SET)
#define hc595_stcp_low()   HAL_GPIO_WritePin(PORT_STCP, PIN_STCP, GPIO_PIN_RESET)
#define hc595_stcp_high()  HAL_GPIO_WritePin(PORT_STCP, PIN_STCP, GPIO_PIN_SET)

#endif
