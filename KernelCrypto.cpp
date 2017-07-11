#include <error.h>
#include <endian.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <errno.h>
#include <memory.h>
#include <string.h>

#include "Trigger.h"
typedef unsigned uint_32;
#define SOL_ALG 279

//static void DoKernelSymmetric ( const char* name, uint_8 const* input, uint_8* output, int datalen, uint_8 const* key, int keylen, FLAGS flags ); 
static std::vector<uint_8> DoKernelSymmetric ( const char* name, std::vector<uint_8>const& input, std::vector<uint_8> const& key, FLAGS flags )
{
	int sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0 );
	
	if ( sockfd == -1 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "socket returned -1");
		
       /*struct sockaddr_alg sa = {
                .salg_family = AF_ALG,
                .salg_type = "skcipher",
		.salg_feat = 0,
		.salg_mask = 0,
                .salg_name = "ecb(aes)"
        }; */
	struct sockaddr_alg sa = { AF_ALG, "skcipher", 0, 0, "" };
	strncpy ( (char*)sa.salg_name, name, sizeof(sa.salg_name));

        if ( bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		error_at_line ( 1, 0, __FILE__, __LINE__,  "bind failed");


        if ( setsockopt (sockfd, SOL_ALG, ALG_SET_KEY, key.data(), key.size() ) == -1 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "setsockopt()=-1, errno=%i", errno );

        int sockfd2 = accept ( sockfd, 0, 0);
        if ( sockfd2 == -1 )
	        error_at_line ( 1, 0, __FILE__, __LINE__,  "accept error=%i\n", errno );

        struct iovec msg_iov = {
                /*.iov_base =*/ (void*)input.data(),
                /*.iov_len =*/ (size_t)input.size(),
        };

        uint_32 msg_control = ALG_OP_ENCRYPT;
        char cmsgbuf[CMSG_SPACE(sizeof(msg_control))];

        struct msghdr msg = {
                /*.msg_name =*/ NULL,
                /*.msg_namelen =*/ 0,
                /*.msg_iov =*/ &msg_iov,
                /*.msg_iovlen =*/ 1,
                /*.msg_control =*/ cmsgbuf,
                /*.msg_controllen =*/ sizeof(cmsgbuf),
                /*.msg_flags =*/ ALG_OP_ENCRYPT,
        };

        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_OP;
        cmsg->cmsg_len = CMSG_LEN(sizeof(msg_control));
        memcpy ( CMSG_DATA(cmsg), &msg_control, sizeof(msg_control));

	std::vector<uint_8> output ( input.size() );
	
	trigger->Raise();
	int ret = sendmsg(sockfd2, &msg, 0/*flags*/);
	if ( ret != input.size() )
		error_at_line ( 1, 0, __FILE__, __LINE__, "sendmesg error" ); 

        int ret3 = read (sockfd2, output.data(), output.size() );
	trigger->Lower();

	if ( ret3 != output.size() )
		error_at_line ( 1, 0, __FILE__, __LINE__, "read error" ); 
	return output;

}
 
std::vector<uint_8> KernelCrypto::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	if ( key.size() == 8 )	
		return DoKernelSymmetric ( "ecb(des)", input, key, flags );
	else if ( key.size() == 16 )
	{
		std::vector<uint_8> keycopy = key;
		keycopy.insert ( keycopy.end(), key.begin(), key.begin() + 8 );
		return DoKernelSymmetric ( "ecb(des3_ede)", input, keycopy, flags );
	}
	else
		return DoKernelSymmetric ( "ecb(des3_ede)", input, key, flags );
}


std::vector<uint_8> KernelCrypto::DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const & key, FLAGS& flags )
{
	return DoKernelSymmetric ( "ecb(aes)", input, key, flags );
}
