const fs = require('fs');
const logFile = 'nativeAriesAskar_runtime1.log';
const logVariables = (funcName, ...args) => {
  const logEntry = `Timestamp: ${new Date().toISOString()}\nFunction: ${funcName}\nArguments: ${JSON.stringify(args)}\n\n`;
  fs.appendFileSync(logFile, logEntry);
};
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeJSAriesAskar = void 0;
const aries_askar_shared_1 = require("@hyperledger/aries-askar-shared");
const ffi_1 = require("./ffi");
const library_1 = require("./library");
function handleNullableReturnPointer(returnValue) {
    if (returnValue.address() === 0)
        return null;
    return returnValue.deref();
}
function handleReturnPointer(returnValue) {
    if (returnValue.address() === 0) {
        throw aries_askar_shared_1.AriesAskarError.customError({ message: 'Unexpected null pointer' });
    }
    return returnValue.deref();
}
class NodeJSAriesAskar {
    constructor() {
        this.promisify = async (method) => {
            return new Promise((resolve, reject) => {
                const cb = (id, errorCode) => {
                    (0, ffi_1.deallocateCallbackBuffer)(id);
                    try {
                        this.handleError(errorCode);
                    }
                    catch (e) {
                        reject(e);
                    }
                    resolve();
                };
                const { nativeCallback, id } = (0, ffi_1.toNativeCallback)(cb);
                method(nativeCallback, +id);
            });
        };
        this.promisifyWithResponse = async (method, responseFfiType = ffi_1.FFI_STRING) => {
            return new Promise((resolve, reject) => {
                const cb = (id, errorCode, response) => {
                    logVariables("promisifyWithResponse", method, responseFfiType, id, errorCode, response);
                    (0, ffi_1.deallocateCallbackBuffer)(id);
                    if (errorCode !== 0) {
                        const error = this.getAriesAskarError(errorCode);
                        reject(error);
                    }
                    if (typeof response === 'string') {
                        if (responseFfiType === ffi_1.FFI_STRING)
                            resolve(response);
                        try {
                            resolve(JSON.parse(response));
                        }
                        catch (error) {
                            reject(error);
                        }
                    }
                    else if (typeof response === 'number') {
                        resolve(response);
                    }
                    else if (response instanceof Buffer) {
                        if (response.address() === 0)
                            resolve(null);
                        resolve(response);
                    }
                    reject(aries_askar_shared_1.AriesAskarError.customError({ message: `could not parse return type properly (type: ${typeof response})` }));
                };
                
                const { nativeCallback, id } = (0, ffi_1.toNativeCallbackWithResponse)(cb, responseFfiType);
                const errorCode = method(nativeCallback, +id);
                if (errorCode !== 0)
                    (0, ffi_1.deallocateCallbackBuffer)(+id);
                this.handleError(errorCode);
            });
        };
    }
    /**
     * Fetch the error from the native library and throw it as a JS error
     *
     * NOTE:
     * Checks whether the error code of the returned error matches the error code that was passed to the function.
     * If it doesn't, we throw an error with the original errorCode, and a custom message explaining we weren't able
     * to retrieve the error message from the native library. This should however not break functionality as long as
     * error codes are used rather than error messages for error handling.
     *
     */
    getAriesAskarError(errorCode) {
        const error = this.getCurrentError();
        if (error.code !== errorCode) {
            return new aries_askar_shared_1.AriesAskarError({
                code: errorCode,
                message: 'Error details have already been overwritten on the native side, unable to retrieve error message for the error',
            });
        }
        return new aries_askar_shared_1.AriesAskarError(error);
    }
    handleError(errorCode) {
        if (errorCode === 0)
            return;
        throw this.getAriesAskarError(errorCode);
    }
    get nativeAriesAskar() {
        return (0, library_1.getNativeAriesAskar)();
    }
    version() {
        return this.nativeAriesAskar.askar_version()
logVariables('nativeAriesAskar.askar_version', );;
    }
    getCurrentError() {
        const error = (0, ffi_1.allocateStringBuffer)();
        this.nativeAriesAskar.askar_get_current_error(error)
logVariables('nativeAriesAskar.askar_get_current_error', error);;
        const serializedError = handleReturnPointer(error);
        return JSON.parse(serializedError);
    }
    clearCustomLogger() {
        this.nativeAriesAskar.askar_clear_custom_logger()
logVariables('nativeAriesAskar.askar_clear_custom_logger', );;
    }
    // TODO: the id has to be deallocated when its done, but how?
    setCustomLogger({ logLevel, flush = false, enabled = false, logger }) {
        const { id, nativeCallback } = (0, ffi_1.toNativeLogCallback)(logger);
        // TODO: flush and enabled are just guessed
        const errorCode = this.nativeAriesAskar.askar_set_custom_logger(0, nativeCallback, +enabled, +flush, logLevel)
logVariables('nativeAriesAskar.askar_set_custom_logger', 0, nativeCallback, +enabled, +flush, logLevel);;
        this.handleError(errorCode);
        (0, ffi_1.deallocateCallbackBuffer)(+id);
    }
    setDefaultLogger() {
        const errorCode = this.nativeAriesAskar.askar_set_default_logger()
logVariables('nativeAriesAskar.askar_set_default_logger', );;
        this.handleError(errorCode);
    }
    setMaxLogLevel(options) {
        const { logLevel } = (0, ffi_1.serializeArguments)(options);
        const errorCode = this.nativeAriesAskar.askar_set_max_log_level(logLevel)
logVariables('nativeAriesAskar.askar_set_max_log_level', logLevel);;
        this.handleError(errorCode);
    }
    entryListCount(options) {
        const { entryListHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateInt32Buffer)();
        const errorCode = this.nativeAriesAskar.askar_entry_list_count(entryListHandle, ret)
logVariables('nativeAriesAskar.askar_entry_list_count', entryListHandle, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    entryListFree(options) {
        const { entryListHandle } = (0, ffi_1.serializeArguments)(options);
        this.nativeAriesAskar.askar_entry_list_free(entryListHandle)
logVariables('nativeAriesAskar.askar_entry_list_free', entryListHandle);;
    }
    entryListGetCategory(options) {
        const { entryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_entry_list_get_category(entryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_entry_list_get_category', entryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    entryListGetName(options) {
        const { entryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_entry_list_get_name(entryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_entry_list_get_name', entryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    entryListGetTags(options) {
        const { entryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_entry_list_get_tags(entryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_entry_list_get_tags', entryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleNullableReturnPointer(ret);
    }
    entryListGetValue(options) {
        const { entryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_entry_list_get_value(entryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_entry_list_get_value', entryListHandle, index, ret);;
        this.handleError(errorCode);
        const byteBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(byteBuffer));
    }
    keyAeadDecrypt(options) {
        const { aad, ciphertext, localKeyHandle, nonce, tag } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_aead_decrypt(localKeyHandle, ciphertext, nonce, tag, aad, ret)
logVariables('nativeAriesAskar.askar_key_aead_decrypt', localKeyHandle, ciphertext, nonce, tag, aad, ret);;
        this.handleError(errorCode);
        const byteBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(byteBuffer));
    }
    keyAeadEncrypt(options) {
        const { localKeyHandle, aad, nonce, message } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateEncryptedBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_aead_encrypt(localKeyHandle, message, nonce, aad, ret)
logVariables('nativeAriesAskar.askar_key_aead_encrypt', localKeyHandle, message, nonce, aad, ret);;
        this.handleError(errorCode);
        const encryptedBuffer = handleReturnPointer(ret);
        return (0, ffi_1.encryptedBufferStructToClass)(encryptedBuffer);
    }
    keyAeadGetPadding(options) {
        const { localKeyHandle, msgLen } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateInt32Buffer)();
        const errorCode = this.nativeAriesAskar.askar_key_aead_get_padding(localKeyHandle, msgLen, ret)
logVariables('nativeAriesAskar.askar_key_aead_get_padding', localKeyHandle, msgLen, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyAeadGetParams(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateAeadParams)();
        const errorCode = this.nativeAriesAskar.askar_key_aead_get_params(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_aead_get_params', localKeyHandle, ret);;
        this.handleError(errorCode);
        return new aries_askar_shared_1.AeadParams(handleReturnPointer(ret));
    }
    keyAeadRandomNonce(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_aead_random_nonce(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_aead_random_nonce', localKeyHandle, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyConvert(options) {
        const { localKeyHandle, algorithm } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_convert(localKeyHandle, algorithm, ret)
logVariables('nativeAriesAskar.askar_key_convert', localKeyHandle, algorithm, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyCryptoBox(options) {
        const { nonce, message, recipientKey, senderKey } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_crypto_box(recipientKey, senderKey, message, nonce, ret)
logVariables('nativeAriesAskar.askar_key_crypto_box', recipientKey, senderKey, message, nonce, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyCryptoBoxOpen(options) {
        const { nonce, message, senderKey, recipientKey } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_crypto_box_open(recipientKey, senderKey, message, nonce, ret)
logVariables('nativeAriesAskar.askar_key_crypto_box_open', recipientKey, senderKey, message, nonce, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyCryptoBoxRandomNonce() {
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_crypto_box_random_nonce(ret)
logVariables('nativeAriesAskar.askar_key_crypto_box_random_nonce', ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyCryptoBoxSeal(options) {
        const { message, localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_crypto_box_seal(localKeyHandle, message, ret)
logVariables('nativeAriesAskar.askar_key_crypto_box_seal', localKeyHandle, message, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyCryptoBoxSealOpen(options) {
        const { ciphertext, localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_crypto_box_seal_open(localKeyHandle, ciphertext, ret)
logVariables('nativeAriesAskar.askar_key_crypto_box_seal_open', localKeyHandle, ciphertext, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyDeriveEcdh1pu(options) {
        const { senderKey, recipientKey, algorithm, algId, apu, apv, ccTag, ephemeralKey, receive } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_derive_ecdh_1pu(algorithm, ephemeralKey, senderKey, recipientKey, algId, apu, apv, ccTag, receive, ret)
logVariables('nativeAriesAskar.askar_key_derive_ecdh_1pu', algorithm, ephemeralKey, senderKey, recipientKey, algId, apu, apv, ccTag, receive, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyDeriveEcdhEs(options) {
        const { receive, apv, apu, algId, recipientKey, ephemeralKey, algorithm } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_derive_ecdh_es(algorithm, ephemeralKey, recipientKey, algId, apu, apv, receive, ret)
logVariables('nativeAriesAskar.askar_key_derive_ecdh_es', algorithm, ephemeralKey, recipientKey, algId, apu, apv, receive, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyEntryListCount(options) {
        const { keyEntryListHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateInt32Buffer)();
        const errorCode = this.nativeAriesAskar.askar_key_entry_list_count(keyEntryListHandle, ret)
logVariables('nativeAriesAskar.askar_key_entry_list_count', keyEntryListHandle, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyEntryListFree(options) {
        const { keyEntryListHandle } = (0, ffi_1.serializeArguments)(options);
        this.nativeAriesAskar.askar_key_entry_list_free(keyEntryListHandle)
logVariables('nativeAriesAskar.askar_key_entry_list_free', keyEntryListHandle);;
    }
    keyEntryListGetAlgorithm(options) {
        const { keyEntryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_entry_list_get_algorithm(keyEntryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_key_entry_list_get_algorithm', keyEntryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyEntryListGetMetadata(options) {
        const { keyEntryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_entry_list_get_metadata(keyEntryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_key_entry_list_get_metadata', keyEntryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleNullableReturnPointer(ret);
    }
    keyEntryListGetName(options) {
        const { keyEntryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_entry_list_get_name(keyEntryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_key_entry_list_get_name', keyEntryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyEntryListGetTags(options) {
        const { keyEntryListHandle, index } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_entry_list_get_tags(keyEntryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_key_entry_list_get_tags', keyEntryListHandle, index, ret);;
        this.handleError(errorCode);
        return handleNullableReturnPointer(ret);
    }
    keyEntryListLoadLocal(options) {
        const { index, keyEntryListHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_entry_list_load_local(keyEntryListHandle, index, ret)
logVariables('nativeAriesAskar.askar_key_entry_list_load_local', keyEntryListHandle, index, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyFree(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        this.nativeAriesAskar.askar_key_free(localKeyHandle)
logVariables('nativeAriesAskar.askar_key_free', localKeyHandle);;
    }
    keyFromJwk(options) {
        const { jwk } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_from_jwk(jwk, ret)
logVariables('nativeAriesAskar.askar_key_from_jwk', jwk, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyFromKeyExchange(options) {
        const { algorithm, pkHandle, skHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_from_key_exchange(algorithm, skHandle, pkHandle, ret)
logVariables('nativeAriesAskar.askar_key_from_key_exchange', algorithm, skHandle, pkHandle, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyFromPublicBytes(options) {
        const { publicKey, algorithm } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_from_public_bytes(algorithm, publicKey, ret)
logVariables('nativeAriesAskar.askar_key_from_public_bytes', algorithm, publicKey, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyFromSecretBytes(options) {
        const { secretKey, algorithm } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_from_secret_bytes(algorithm, secretKey, ret)
logVariables('nativeAriesAskar.askar_key_from_secret_bytes', algorithm, secretKey, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyFromSeed(options) {
        const { algorithm, method, seed } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_from_seed(algorithm, seed, method, ret)
logVariables('nativeAriesAskar.askar_key_from_seed', algorithm, seed, method, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyGenerate(options) {
        const { algorithm, ephemeral } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_generate(algorithm, ephemeral, ret)
logVariables('nativeAriesAskar.askar_key_generate', algorithm, ephemeral, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyGetAlgorithm(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_algorithm(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_get_algorithm', localKeyHandle, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyGetEphemeral(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateInt32Buffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_ephemeral(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_get_ephemeral', localKeyHandle, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyGetJwkPublic(options) {
        const { localKeyHandle, algorithm } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_jwk_public(localKeyHandle, algorithm, ret)
logVariables('nativeAriesAskar.askar_key_get_jwk_public', localKeyHandle, algorithm, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyGetJwkSecret(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_jwk_secret(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_get_jwk_secret', localKeyHandle, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyGetJwkThumbprint(options) {
        const { localKeyHandle, algorithm } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_jwk_thumbprint(localKeyHandle, algorithm, ret)
logVariables('nativeAriesAskar.askar_key_get_jwk_thumbprint', localKeyHandle, algorithm, ret);;
        this.handleError(errorCode);
        return handleReturnPointer(ret);
    }
    keyGetPublicBytes(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_public_bytes(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_get_public_bytes', localKeyHandle, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyGetSecretBytes(options) {
        const { localKeyHandle } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_get_secret_bytes(localKeyHandle, ret)
logVariables('nativeAriesAskar.askar_key_get_secret_bytes', localKeyHandle, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keySignMessage(options) {
        const { localKeyHandle, message, sigType } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateSecretBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_sign_message(localKeyHandle, message, sigType, ret)
logVariables('nativeAriesAskar.askar_key_sign_message', localKeyHandle, message, sigType, ret);;
        this.handleError(errorCode);
        const secretBuffer = handleReturnPointer(ret);
        return new Uint8Array((0, ffi_1.secretBufferToBuffer)(secretBuffer));
    }
    keyUnwrapKey(options) {
        const { localKeyHandle, algorithm, ciphertext, nonce, tag } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocatePointer)();
        const errorCode = this.nativeAriesAskar.askar_key_unwrap_key(localKeyHandle, algorithm, ciphertext, nonce, tag, ret)
logVariables('nativeAriesAskar.askar_key_unwrap_key', localKeyHandle, algorithm, ciphertext, nonce, tag, ret);;
        this.handleError(errorCode);
        const handle = handleReturnPointer(ret);
        return new aries_askar_shared_1.LocalKeyHandle(handle);
    }
    keyVerifySignature(options) {
        const { localKeyHandle, sigType, message, signature } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateInt8Buffer)();
        const errorCode = this.nativeAriesAskar.askar_key_verify_signature(localKeyHandle, message, signature, sigType, ret)
logVariables('nativeAriesAskar.askar_key_verify_signature', localKeyHandle, message, signature, sigType, ret);;
        this.handleError(errorCode);
        return Boolean(handleReturnPointer(ret));
    }
    keyWrapKey(options) {
        const { localKeyHandle, nonce, other } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateEncryptedBuffer)();
        const errorCode = this.nativeAriesAskar.askar_key_wrap_key(localKeyHandle, other, nonce, ret)
logVariables('nativeAriesAskar.askar_key_wrap_key', localKeyHandle, other, nonce, ret);;
        this.handleError(errorCode);
        const encryptedBuffer = handleReturnPointer(ret);
        return (0, ffi_1.encryptedBufferStructToClass)(encryptedBuffer);
    }
    scanFree(options) {
        const { scanHandle } = (0, ffi_1.serializeArguments)(options);
        const errorCode = this.nativeAriesAskar.askar_scan_free(scanHandle)
logVariables('nativeAriesAskar.askar_scan_free', scanHandle);;
        this.handleError(errorCode);
    }
    async scanNext(options) {
        const { scanHandle } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_scan_next(scanHandle, cb, cbId), ffi_1.FFI_ENTRY_LIST_HANDLE);
        logVariables('nativeAriesAskar.askar_scan_next', scanHandle);
        return aries_askar_shared_1.EntryListHandle.fromHandle(handle);
    }
    async scanStart(options) {
        const { category, limit, offset, profile, storeHandle, tagFilter } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_scan_start(storeHandle, profile, category, tagFilter, +offset || 0, +limit || -1, cb, cbId), ffi_1.FFI_SCAN_HANDLE);
logVariables('nativeAriesAskar.askar_scan_start', storeHandle, profile, category, tagFilter, +offset || 0, +limit || -1);
        return aries_askar_shared_1.ScanHandle.fromHandle(handle);
    }
    async sessionClose(options) {
        const { commit, sessionHandle } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_session_close', sessionHandle, commit);
        return await this.promisify((cb, cbId) => this.nativeAriesAskar.askar_session_close(sessionHandle, commit, cb, cbId));

    }
    async sessionCount(options) {
        const { sessionHandle, tagFilter, category } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_count(sessionHandle, category, tagFilter, cb, cbId), ffi_1.FFI_INT64);
logVariables('nativeAriesAskar.askar_session_count', sessionHandle, category, tagFilter);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    async sessionFetch(options) {
        const { name, category, sessionHandle, forUpdate } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_fetch(sessionHandle, category, name, forUpdate, cb, cbId), ffi_1.FFI_ENTRY_LIST_HANDLE);
logVariables('nativeAriesAskar.askar_session_fetch', sessionHandle, category, name, forUpdate);
        return aries_askar_shared_1.EntryListHandle.fromHandle(handle);
    }
    async sessionFetchAll(options) {
        const { forUpdate, sessionHandle, tagFilter, limit, category } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_fetch_all(sessionHandle, category, tagFilter, +limit || -1, forUpdate, cb, cbId), ffi_1.FFI_ENTRY_LIST_HANDLE);
logVariables('nativeAriesAskar.askar_session_fetch_all', sessionHandle, category, tagFilter, +limit || -1, forUpdate);
        return aries_askar_shared_1.EntryListHandle.fromHandle(handle);
    }
    async sessionFetchAllKeys(options) {
        const { forUpdate, limit, tagFilter, sessionHandle, algorithm, thumbprint } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_fetch_all_keys(sessionHandle, algorithm, thumbprint, tagFilter, +limit || -1, forUpdate, cb, cbId), ffi_1.FFI_KEY_ENTRY_LIST_HANDLE);
logVariables('nativeAriesAskar.askar_session_fetch_all_keys', sessionHandle, algorithm, thumbprint, tagFilter, +limit || -1, forUpdate);
        return aries_askar_shared_1.KeyEntryListHandle.fromHandle(handle);
    }
    async sessionFetchKey(options) {
        const { forUpdate, sessionHandle, name } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_fetch_key(sessionHandle, name, forUpdate, cb, cbId), ffi_1.FFI_KEY_ENTRY_LIST_HANDLE);
logVariables('nativeAriesAskar.askar_session_fetch_key', sessionHandle, name, forUpdate);
        return aries_askar_shared_1.KeyEntryListHandle.fromHandle(handle);
    }
    async sessionInsertKey(options) {
        const { name, sessionHandle, expiryMs, localKeyHandle, metadata, tags } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_session_insert_key', sessionHandle, localKeyHandle, name, metadata, tags, +expiryMs || -1);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_session_insert_key(sessionHandle, localKeyHandle, name, metadata, tags, +expiryMs || -1, cb, cbId));
    }
    async sessionRemoveAll(options) {
        const { sessionHandle, tagFilter, category } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_remove_all(sessionHandle, category, tagFilter, cb, cbId), ffi_1.FFI_INT64);
        logVariables('nativeAriesAskar.askar_session_remove_all', sessionHandle, category, tagFilter);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    async sessionRemoveKey(options) {
        const { sessionHandle, name } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_session_remove_key', sessionHandle, name);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_session_remove_key(sessionHandle, name, cb, cbId));

    }
    async sessionStart(options) {
        const { storeHandle, profile, asTransaction } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_session_start(storeHandle, profile, asTransaction, cb, cbId), ffi_1.FFI_SESSION_HANDLE);
logVariables('nativeAriesAskar.askar_session_start', storeHandle, profile, asTransaction);
        return aries_askar_shared_1.SessionHandle.fromHandle(handle);
    }
    async sessionUpdate(options) {
        const { name, sessionHandle, category, expiryMs, tags, operation, value } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_session_update', sessionHandle, operation, category, name, value, tags, +expiryMs || -1);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_session_update(sessionHandle, operation, category, name, value, tags, +expiryMs || -1, cb, cbId));

    }
    async sessionUpdateKey(options) {
        const { expiryMs, tags, name, sessionHandle, metadata } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_session_update_key', sessionHandle, name, metadata, tags, +expiryMs || -1);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_session_update_key(sessionHandle, name, metadata, tags, +expiryMs || -1, cb, cbId));

    }
    storeClose(options) {
        const { storeHandle } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_store_close', storeHandle);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_store_close(storeHandle, cb, cbId));

    }
    storeCopyTo(options) {
        const { storeHandle, targetUri, passKey, keyMethod, recreate } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_store_copy', storeHandle, targetUri, keyMethod, passKey, recreate);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_store_copy(storeHandle, targetUri, keyMethod, passKey, recreate, cb, cbId));
    }
    async storeCreateProfile(options) {
        const { storeHandle, profile } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_create_profile(storeHandle, profile, cb, cbId), ffi_1.FFI_STRING);
logVariables('nativeAriesAskar.askar_store_create_profile', storeHandle, profile);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    storeGenerateRawKey(options) {
        const { seed } = (0, ffi_1.serializeArguments)(options);
        const ret = (0, ffi_1.allocateStringBuffer)();
        const errorCode = this.nativeAriesAskar.askar_store_generate_raw_key(seed, ret)
logVariables('nativeAriesAskar.askar_store_generate_raw_key', seed, ret);;
        this.handleError(errorCode);
        return ret.deref();
    }
    async storeGetDefaultProfile(options) {
        const { storeHandle } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_get_default_profile(storeHandle, cb, cbId));
logVariables('nativeAriesAskar.askar_store_get_default_profile', storeHandle);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    async storeGetProfileName(options) {
        const { storeHandle } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_get_profile_name(storeHandle, cb, cbId));
logVariables('nativeAriesAskar.askar_store_get_profile_name', storeHandle);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    async storeListProfiles(options) {
        const { storeHandle } = (0, ffi_1.serializeArguments)(options);
        const listHandle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_list_profiles(storeHandle, cb, cbId), ffi_1.FFI_STRING_LIST_HANDLE);
logVariables('nativeAriesAskar.askar_store_list_profiles', storeHandle);
        if (listHandle === null) {
            throw aries_askar_shared_1.AriesAskarError.customError({ message: 'Invalid handle' });
        }
        const counti32 = (0, ffi_1.allocateInt32Buffer)();
        const errorCode = this.nativeAriesAskar.askar_string_list_count(listHandle, counti32)
logVariables('nativeAriesAskar.askar_string_list_count', listHandle, counti32);;
        this.handleError(errorCode);
        const count = counti32.deref();
        const ret = [];
        const strval = (0, ffi_1.allocateStringBuffer)();
        for (let i = 0; i < count; i++) {
            const errorCode = this.nativeAriesAskar.askar_string_list_get_item(listHandle, i, strval)
logVariables('nativeAriesAskar.askar_string_list_get_item', listHandle, i, strval);;
            this.handleError(errorCode);
            ret.push(strval.deref());
        }
        this.nativeAriesAskar.askar_string_list_free(listHandle)
logVariables('nativeAriesAskar.askar_string_list_free', listHandle);;
        return ret;
    }
    async storeOpen(options) {
        const { profile, keyMethod, passKey, specUri } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_open(specUri, keyMethod, passKey, profile, cb, cbId), ffi_1.FFI_STORE_HANDLE);
logVariables('nativeAriesAskar.askar_store_open', specUri, keyMethod, passKey, profile);
        return aries_askar_shared_1.StoreHandle.fromHandle(handle);
    }
    async storeProvision(options) {
        const { profile, passKey, keyMethod, specUri, recreate } = (0, ffi_1.serializeArguments)(options);
        const handle = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_provision(specUri, keyMethod, passKey, profile, recreate, cb, cbId), ffi_1.FFI_STORE_HANDLE);
logVariables('nativeAriesAskar.askar_store_provision', specUri, keyMethod, passKey, profile, recreate);
        return aries_askar_shared_1.StoreHandle.fromHandle(handle);
    }
    async storeRekey(options) {
        const { passKey, keyMethod, storeHandle } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_store_rekey', storeHandle, keyMethod, passKey);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_store_rekey(storeHandle, keyMethod, passKey, cb, cbId));
    }
    async storeRemove(options) {
        const { specUri } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_remove(specUri, cb, cbId), ffi_1.FFI_INT8);
logVariables('nativeAriesAskar.askar_store_remove', specUri);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    async storeRemoveProfile(options) {
        const { storeHandle, profile } = (0, ffi_1.serializeArguments)(options);
        const response = await this.promisifyWithResponse((cb, cbId) => this.nativeAriesAskar.askar_store_remove_profile(storeHandle, profile, cb, cbId), ffi_1.FFI_INT8);
logVariables('nativeAriesAskar.askar_store_remove_profile', storeHandle, profile);
        return (0, aries_askar_shared_1.handleInvalidNullResponse)(response);
    }
    async storeSetDefaultProfile(options) {
        const { storeHandle, profile } = (0, ffi_1.serializeArguments)(options);
        logVariables('nativeAriesAskar.askar_store_set_default_profile', storeHandle, profile);
        return this.promisify((cb, cbId) => this.nativeAriesAskar.askar_store_set_default_profile(storeHandle, profile, cb, cbId));

    }
    async migrateIndySdk(options) {
        const { specUri, kdfLevel, walletKey, walletName } = (0, ffi_1.serializeArguments)(options);
        await this.promisify((cb, cbId) => this.nativeAriesAskar.askar_migrate_indy_sdk(specUri, walletName, walletKey, kdfLevel, cb, cbId));
logVariables('nativeAriesAskar.askar_migrate_indy_sdk', specUri, walletName, walletKey, kdfLevel);
    }
}
exports.NodeJSAriesAskar = NodeJSAriesAskar;
//# sourceMappingURL=NodeJSAriesAskar.js.map
