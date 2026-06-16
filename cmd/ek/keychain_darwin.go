//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication -framework Security

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

static char *ss_strdup_nsstring(NSString *value) {
	if (value == nil) {
		return NULL;
	}
	const char *utf8 = [value UTF8String];
	if (utf8 == NULL) {
		return NULL;
	}
	size_t len = strlen(utf8);
	char *out = malloc(len + 1);
	if (out == NULL) {
		return NULL;
	}
	memcpy(out, utf8, len + 1);
	return out;
}

static char *ss_status_error(OSStatus status) {
	CFStringRef message = SecCopyErrorMessageString(status, NULL);
	if (message != NULL) {
		NSString *desc = [NSString stringWithFormat:@"%d: %@", (int)status, (__bridge NSString *)message];
		CFRelease(message);
		return ss_strdup_nsstring(desc);
	}
	NSString *fallback = [NSString stringWithFormat:@"OSStatus %d", (int)status];
	return ss_strdup_nsstring(fallback);
}

static char *ss_laerror_error(NSError *error) {
	if (error == nil) {
		return ss_strdup_nsstring(@"authentication failed");
	}
	return ss_strdup_nsstring([error localizedDescription]);
}

static char *ss_authenticate(const char *prompt) {
	@autoreleasepool {
		NSString *promptString = @"Authenticate to unlock go-encrypted-text-kvs";
		if (prompt != NULL) {
			NSString *customPrompt = [NSString stringWithUTF8String:prompt];
			if (customPrompt != nil && [customPrompt length] > 0) {
				promptString = customPrompt;
			}
		}

		LAContext *context = [[LAContext alloc] init];
		context.localizedReason = promptString;

		NSError *canEvaluateError = nil;
		if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&canEvaluateError]) {
			return ss_laerror_error(canEvaluateError);
		}

		__block BOOL success = NO;
		__block NSError *authError = nil;
		dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
		[context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
			localizedReason:promptString
			reply:^(BOOL ok, NSError * _Nullable error) {
				 success = ok;
				 authError = error;
				 dispatch_semaphore_signal(semaphore);
			 }];
		dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
		if (!success) {
			return ss_laerror_error(authError);
		}
		return NULL;
	}
}

static char *ss_keychain_store(const char *account, const unsigned char *data, int dataLen) {
	@autoreleasepool {
		NSString *service = @"go-encrypted-text-kvs";
		NSString *accountString = [NSString stringWithUTF8String:account];
		NSData *valueData = [NSData dataWithBytes:data length:(NSUInteger)dataLen];

		NSDictionary *addQuery = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: accountString,
			(__bridge id)kSecValueData: valueData,
			(__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		};

		OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
		if (status != errSecSuccess) {
			return ss_status_error(status);
		}
		return NULL;
	}
}

static char *ss_keychain_load(const char *account, const char *prompt, unsigned char **outData, int *outLen) {
	@autoreleasepool {
		char *authError = ss_authenticate(prompt);
		if (authError != NULL) {
			return authError;
		}

		NSString *service = @"go-encrypted-text-kvs";
		NSString *accountString = [NSString stringWithUTF8String:account];

		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: accountString,
			(__bridge id)kSecReturnData: @YES,
		};

		CFTypeRef result = NULL;
		OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
		if (status != errSecSuccess) {
			return ss_status_error(status);
		}

		NSData *data = CFBridgingRelease(result);
		*outLen = (int)[data length];
		*outData = malloc((size_t)*outLen);
		if (*outData == NULL) {
			return ss_strdup_nsstring(@"malloc failed");
		}
		memcpy(*outData, [data bytes], (size_t)*outLen);
		return NULL;
	}
}

static char *ss_keychain_delete(const char *account) {
	@autoreleasepool {
		NSString *service = @"go-encrypted-text-kvs";
		NSString *accountString = [NSString stringWithUTF8String:account];

		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: accountString,
		};

		OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
		if (status != errSecSuccess && status != errSecItemNotFound) {
			return ss_status_error(status);
		}
		return NULL;
	}
}

static int ss_keychain_exists(const char *account, char **outError) {
	@autoreleasepool {
		NSString *service = @"go-encrypted-text-kvs";
		NSString *accountString = [NSString stringWithUTF8String:account];

		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: accountString,
			(__bridge id)kSecReturnAttributes: @YES,
		};

		CFTypeRef result = NULL;
		OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
		if (result != NULL) {
			CFRelease(result);
		}
		if (status == errSecSuccess) {
			return 1;
		}
		if (status == errSecItemNotFound) {
			return 0;
		}
		*outError = ss_status_error(status);
		return -1;
	}
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

func keychainStore(keyID string, key []byte) error {
	account := C.CString(keyID)
	defer C.free(unsafe.Pointer(account))
	data := C.CBytes(key)
	defer C.free(data)

	if errStr := C.ss_keychain_store(account, (*C.uchar)(data), C.int(len(key))); errStr != nil {
		defer C.free(unsafe.Pointer(errStr))
		message := C.GoString(errStr)
		if strings.Contains(message, "-25299") || strings.Contains(strings.ToLower(message), "duplicate") {
			return fmt.Errorf("decrypt key already exists in OS keystore")
		}
		return fmt.Errorf("%s", message)
	}
	return nil
}

func keychainLoad(keyID string, prompt string) ([]byte, error) {
	account := C.CString(keyID)
	defer C.free(unsafe.Pointer(account))
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	var outData *C.uchar
	var outLen C.int
	if errStr := C.ss_keychain_load(account, cPrompt, &outData, &outLen); errStr != nil {
		defer C.free(unsafe.Pointer(errStr))
		return nil, fmt.Errorf("%s", C.GoString(errStr))
	}
	defer C.free(unsafe.Pointer(outData))
	return C.GoBytes(unsafe.Pointer(outData), outLen), nil
}

func keychainDelete(keyID string) error {
	account := C.CString(keyID)
	defer C.free(unsafe.Pointer(account))

	if errStr := C.ss_keychain_delete(account); errStr != nil {
		defer C.free(unsafe.Pointer(errStr))
		return fmt.Errorf("%s", C.GoString(errStr))
	}
	return nil
}
func keychainExists(keyID string) bool {
	account := C.CString(keyID)
	defer C.free(unsafe.Pointer(account))

	var errStr *C.char
	exists := C.ss_keychain_exists(account, &errStr)
	if errStr != nil {
		defer C.free(unsafe.Pointer(errStr))
	}
	return exists == 1
}
