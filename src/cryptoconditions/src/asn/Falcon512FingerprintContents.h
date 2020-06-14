
#ifndef	_Falcon512FingerprintContents_H_
#define	_Falcon512FingerprintContents_H_


#include "asn_application.h"

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Falcon512FingerprintContents */
typedef struct Falcon512FingerprintContents {
	OCTET_STRING_t	 publicKey;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Falcon512FingerprintContents_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Falcon512FingerprintContents;

#ifdef __cplusplus
}
#endif

#endif	/* _Falcon512FingerprintContents_H_ */
#include <asn_internal.h>
