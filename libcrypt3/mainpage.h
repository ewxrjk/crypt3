/** @mainpage libcrypt3
 *
 * This library provide access to the password encryption algorithms
 * provided by crypt(3) on some platforms.
 *
 * **Storing a password**
 *
 * To encrypt a password:
 * - Select the encryption algorithm.
 * - Generate a random salt, either manually or using @ref libcrypt3_pick_salt.
 * - Encrypt the password, using @ref libcrypt3_crypt_r or @ref
 * libcrypt3_crypt.
 *
 * The resulting encrypted password should be stored.
 *
 * **Verifying a password**
 *
 * To verify a candidate password:
 * - Retrieve the encrypted password from the first step.
 * - Encrypt the candidate password, with the encrypted password as the salt
 * argument, using @ref libcrypt3_crypt_r or @ref libcrypt3_crypt.
 * - Compare the result with the encrypted password. If they match then the
 * candidate password was correct.
 *
 * The overall process is as shown:
 *
 * @image html usage.svg
 *
 * **Algorithm Selection**
 *
 * The purpose of this library is to support legacy password formats in a
 * somewhat portable way. As such algorithm selection is expected to be
 * constrained by existing decisions in typical use cases, and there is no
 * built-in default.
 *
 * Where there is a choice, later algorithms are generally better,
 * i.e. pick the first of SHA512, SHA256, MD5 or DES that will work.
 *
 * For an application that is _not_ constrained to use a legacy password
 * format, consult a reference such as <a
 * href="https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html">Cryptographic
 * Right Answers</a>.
 */
