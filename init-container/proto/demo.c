#include <pb_encode.h>
#include <pb_decode.h>
#include "vm-agent.pb.h"

int printf(const char *msg, ...) {
  return 0;
}


int main()
{
    /* This is the buffer where we will store our message. */
    uint8_t buffer[128];
    size_t message_length;
    bool status;
    
    /* Encode our message */
    {
        Request message = Request_init_zero;
        
        /* Create a stream that will write to our buffer. */
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        /* Fill in the lucky number */
        message.id = 13;
        message.which_Command = Request_quit_tag;
        
        /* Now we are ready to encode the message! */
        status = pb_encode(&stream, Request_fields, &message);
        message_length = stream.bytes_written;
        
        /* Then just check for any errors.. */
        if (!status)
        {
            printf("Encoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }
    }
    
    
    {
        Request message = Request_init_zero;
        
        /* Create a stream that reads from the buffer. */
        pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);
        
        /* Now we are ready to decode the message. */
        status = pb_decode(&stream, Request_fields, &message);
        
        /* Check for errors... */
        if (!status)
        {
            printf("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }
        
        /* Print the data contained in the message. */
        printf("mesage ID=%d, command=%d\n", (int)message.id, (int)message.which_Command);
    }
    
    return 0;
}

