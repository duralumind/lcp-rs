/**
 * Readium LCP Decryption Library - C FFI Header
 *
 * This header provides the C interface for the LCP decryption library.
 * Use with LuaJIT FFI or any C-compatible language.
 */

#ifndef LCP_DECRYPT_H
#define LCP_DECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if an EPUB file is LCP encrypted.
 *
 * @param epub_path Path to the EPUB file (null-terminated string)
 * @return 1 if encrypted, 0 if not encrypted, -1 on error
 */
int lcp_is_encrypted(const char* epub_path);

/**
 * Decrypt an LCP-encrypted EPUB to a new file.
 *
 * @param epub_path Path to the encrypted EPUB file (null-terminated string)
 * @param output_path Path where decrypted EPUB will be written (null-terminated string)
 * @param passphrase The user's passphrase (null-terminated string)
 * @return 0 on success, 1 if wrong passphrase, 2 if not encrypted, -1 on other error
 */
int lcp_decrypt_epub(const char* epub_path, const char* output_path, const char* passphrase);

/**
 * Get the last error message.
 *
 * @return Pointer to null-terminated error string, or NULL if no error.
 *         Valid until next lcp_* function call.
 */
const char* lcp_get_error(void);

#ifdef __cplusplus
}
#endif

#endif /* READIUM_LCP_H */
