#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <error.h>
#include <unistd.h>
#include <errno.h>

#include "Trigger.h"

void StdOutTrigger::Raise()
{
	printf ( "Trigger Raised\n" );
}
void StdOutTrigger::Lower()
{
	printf ( "Trigger Lowered\n" );
}


static unsigned* pinconf1; 
#define OE_ADDR 0x134
#define GPIO_DATAOUT 0x13C
#define GPIO_DATAIN 0x138
#define GPIO0_ADDR 0x44E07000
#define GPIO1_ADDR 0x4804C000
#define GPIO2_ADDR 0x481AC000
#define GPIO3_ADDR 0x481AF000

void BeagleBoneTrigger::Init()
{
 	int fd = open("/dev/mem",O_RDWR | O_SYNC);
	
	if ( fd <= 0 )
	{
		printf ( "Unable to open /dev/mem, aborting\n" );
		exit(0);
	}
        pinconf1 = (unsigned *) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, GPIO1_ADDR);

        //set all pins to inputs, except pin 28
        pinconf1[OE_ADDR/4] &= (0xFFFFFFFF ^ (1<<28));
}


void BeagleBoneTrigger::Raise(){
        pinconf1[GPIO_DATAOUT/4] |= (1<<28);
        //sleep(1);
}

void BeagleBoneTrigger::Lower(){
        pinconf1[GPIO_DATAOUT/4] ^= (1<<28);
        //sleep(1);
}

SysGpioTrigger::SysGpioTrigger()
{
#define PORT_PIN_DIR  "/sys/class/gpio/gpio60/"
	const char* directionFilename = PORT_PIN_DIR "direction";
	const char* valueFilename = PORT_PIN_DIR "value";

	int directionfd = open ( directionFilename, O_WRONLY );
	if ( directionfd < 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "open %s returned error %i", directionFilename, directionfd );

	int rc = write ( directionfd, "out", 3 );
	if ( rc != 3  )
		error_at_line ( 1, 0, __FILE__, __LINE__, "write returned error %i rc=%i", errno, rc );

	valuefd = open ( valueFilename, O_WRONLY );
	if ( valuefd < 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "open %s returned error %i", valueFilename, valuefd );
	
}

void SysGpioTrigger::Raise() 
{
	int rc = write ( valuefd, "1", 1 );	
	if ( rc != 1 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "write returned erro %i fd=%i errno=%i", rc, valuefd, errno );
}
void SysGpioTrigger::Lower() 
{
	int rc = write ( valuefd, "0", 1 );
	if ( rc != 1 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "write returned erro %i", rc );
}
