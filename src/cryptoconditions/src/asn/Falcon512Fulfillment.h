
#ifndef	_Falcon512Fulfillment_H_ 
#define	_Falcon512Fulfillment_H_ 


#include "asn_application.h"

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Falcon5121Fulfillment */
typedef struct Falcon512Fulfillment {
	OCTET_STRING_t	 publicKey;
	OCTET_STRING_t	 signature;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Falcon512Fulfillment_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Falcon512Fulfillment;

#ifdef __cplusplus
}
#endif

#endif	/* _Falcon512Fulfillment_H_ */
#include <asn_internal.h>