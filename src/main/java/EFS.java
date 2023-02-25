import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

/**
 * @author Hunter Sullivan
 * @netid hxs200010
 * @email hunter.sullivan@utdallas.edu
 */
public class EFS extends Utility {
    
    public static enum HashAlg {
        SHA256,
        SHA384,
        SHA512
    }
    
    private HashAlg PASSWORD_HASH_ALG = HashAlg.SHA256;
    private HashAlg METADATA_DIGEST_ALG = HashAlg.SHA256;
    private HashAlg FILE_DIGEST_ALG = HashAlg.SHA256;
    private HashAlg PBKDF2_HASH_ALG = HashAlg.SHA256;
    
    private int N_USERNAME_BYTES = 128;
    private int N_SALT_BYTES = 16;
    private int N_FEK_BYTES = 16;
    private int N_LENGTH_BYTES = 4;
    private int AES_BLOCK_SIZE = 128;
    private int N_PBDFK2_ITERATIONS = 1000;
    private int DERIVED_KEY_LENGTH = 256;    // setting to same output length of SHA
    
    private Charset CHARACTER_SET = StandardCharsets.US_ASCII;
    private ByteBuffer intByteBuffer = ByteBuffer.allocate(Integer.BYTES);
    private Logger logger = Logger.getLogger(EFS.class.getName()); 
    
    /**
     * Get the hash alg block size in bytes.
     * @param h
     * @return
     * @throws Exception
     */
    public int getHashBlockSize(HashAlg h) throws Exception {
        if (h == HashAlg.SHA256) {
            return 64;
        } else if (h == HashAlg.SHA384) {
            return 128;
        } else if (h == HashAlg.SHA512) {
            return 128;
        }
        throw new Exception("Unsupported hash algorithm: " + h);
    }
    
    /**
     * Get the hash alg output size in bytes.
     * @param h
     * @return
     * @throws Exception
     */
    public int getHashOutputSize(HashAlg h) throws Exception {
        if (h == HashAlg.SHA256) {
            return 32;
        } else if (h == HashAlg.SHA384) {
            return 48;
        } else if (h == HashAlg.SHA512) {
            return 64;
        }
        throw new Exception("Unsupported hash algorithm: " + h);
    }
    
    /**
     * Get the size of the secret metadata in bytes.
     * @return number of bytes.
     */
    public int getEncryptedSecretMetadataSize() throws Exception {
        // The encryption algorithm requires the message size to be multiple of the key.
        int result = getHashOutputSize(PASSWORD_HASH_ALG) + N_FEK_BYTES + N_LENGTH_BYTES;

        while (result % N_FEK_BYTES != 0)
        {
            result += 1;
        }

        return result;
    }
    
    /**
     * Computes the size of the entire plaintext metadata block in bytes.
     * @return number of bytes
     * @throws Exception
     */
    public int getMetadataSize() throws Exception {
        return N_USERNAME_BYTES + N_SALT_BYTES + getHashOutputSize(PASSWORD_HASH_ALG) + N_FEK_BYTES + N_LENGTH_BYTES + getHashOutputSize(METADATA_DIGEST_ALG) + getHashOutputSize(FILE_DIGEST_ALG);
    }
    
    /**
     * Returns the number of bytes in the plaintext secret metadata section.
     * @return number of bytes
     * @throws Exception
     */
    public int getPlaintextSecretMetadataSize() throws Exception {
        return getHashOutputSize(PASSWORD_HASH_ALG) + N_FEK_BYTES + N_LENGTH_BYTES;
    }
    
    /**
     * Compute hash.
     * @param key
     * @param hashAlg
     * @return
     * @throws Exception
     */
    public byte[] computeHash(byte[] key, HashAlg hashAlg) throws Exception {
        if (hashAlg == HashAlg.SHA256) {
            return hash_SHA256(key);
        } else if (hashAlg == HashAlg.SHA384) {
            return hash_SHA384(key);
        } else if (hashAlg == HashAlg.SHA512) {
            return hash_SHA512(key);
        } else {
            throw new Exception("Unsupported hash alg: "+ hashAlg);
        }
    }
    
    /**
     * Pad byte array to fixed size.
     * @param bytes
     * @param size
     * @return
     * @throws Exception
     */
    public byte[] padByteArray(byte[] bytes, int size) throws Exception {
        if (size < bytes.length) {
            throw new Exception("Cannot pad byte array to smaller size.");
        }
        if (bytes.length % size == 0) {
            return bytes;
        }
        byte[] paddedArray = new byte[size];
        System.arraycopy(bytes, 0, paddedArray, 0, bytes.length);
        return paddedArray;
    }
    
    /**
     * Generates new password salt.
     * @return Byte array ASCII-encoded.
     */
    public String getNewPasswordSalt() {
        int leftLimit = 33;   // character '!'
        int rightLimit = 126; // letter '~'
        
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(N_SALT_BYTES);
        
        for (int i = 0; i < N_SALT_BYTES; i++) {
            int randomLimitedInt = leftLimit + (int) 
              (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        return buffer.toString();
    }
    
    /**
     * Converts int to byte array.
     * @param x
     * @return Byte array representation.
     */
    public byte[] integerToBytes(int x) {
        intByteBuffer.putInt(x);
        return intByteBuffer.array();
    }
    
    /**
     * Converts byte array to int.
     * @param bytes
     * @return Int representation.
     */
    public int bytesToInteger(byte[] bytes) {
        intByteBuffer.put(bytes, 0, bytes.length);
        intByteBuffer.flip();
        return intByteBuffer.getInt();
    }
    
    /**
     * Hash the password.
     * @param password
     * @param salt
     * @return Hash of the password as byte array.
     */
    public byte[] getPasswordHash(String password, String salt) throws Exception {
        String message = password + salt;
        
        if (PASSWORD_HASH_ALG == HashAlg.SHA256) {
            return hash_SHA256(message.getBytes(CHARACTER_SET));
            
        } else if (PASSWORD_HASH_ALG == HashAlg.SHA384) {
            return hash_SHA384(message.getBytes(CHARACTER_SET));
            
        } else if (PASSWORD_HASH_ALG == HashAlg.SHA512) {
            return hash_SHA512(message.getBytes(CHARACTER_SET));
            
        } else {
            throw new Exception("Unsupported hash algorithm: " + PASSWORD_HASH_ALG);
        }
    }
    
    /**
     * Fetch salt field from metadata.
     * @param metadata
     * @return Salt as byte array.
     */
    public byte[] getSaltFromMetadata(byte[] metadata) {
        byte[] salt = new byte[N_SALT_BYTES];
        System.arraycopy(metadata, N_USERNAME_BYTES, salt, 0, N_SALT_BYTES);
        return salt;
    }
    
    /**
     * Fetch file length field from plaintext metadata.
     * @param metadata Completely plaintext metadata.
     * @return length field
     */
    public int getLengthFromMetadata(byte[] metadata) throws Exception {
        int index = getMetadataSize() - getHashOutputSize(METADATA_DIGEST_ALG) - getHashOutputSize(FILE_DIGEST_ALG);
        byte[] result = new byte[N_LENGTH_BYTES];
        System.arraycopy(metadata, index, result, 0, N_LENGTH_BYTES);
        
        ByteBuffer wrapped = ByteBuffer.wrap(result); // big-endian by default
        return wrapped.getInt();
    }
    
    /**
     * Fetch file metadata.
     * @param filename
     * @return Metadata as byte array.
     * @throws Exception
     */
    public byte[] getFileMetadata(String filename) throws Exception {
        dir = new File(filename);
        File file = new File(dir, "0");
        
        if (file.exists()) {
            byte[] contents = read_from_file(file);
            return Arrays.copyOfRange(contents, 0, getMetadataSize());
        } else {
            return null;
        }
    }
    
    /**
     * Encrypts plaintext byte array using CTR mode.
     * @param plaintext
     * @param key
     * @return Ciphertext byte array.
     */
    public byte[] encryptByteArray(byte[] plaintext, byte[] key) throws Exception {
        logger.fine("ENTRY encryptByteArray plaintext.length = " + plaintext.length + " bytes, key.length = " + key.length + " bytes.");
        
        if (plaintext.length > AES_BLOCK_SIZE) {
            logger.fine("Encrypting via CTR mode...");
            
            int nblocks = (int)Math.ceil((double)plaintext.length / AES_BLOCK_SIZE);
            byte[] ciphertext = new byte[nblocks * AES_BLOCK_SIZE];
            int currentPosition = 0; 
            int nextPosition = AES_BLOCK_SIZE;
            
            for (int i = 0; i < nblocks; i++) {
                byte[] nextKey = integerToBytes(bytesToInteger(key) + (int)i);
                byte[] ciphertextBlock = encript_AES(Arrays.copyOfRange(plaintext, currentPosition, nextPosition), nextKey);
                
                System.arraycopy(ciphertextBlock, 0, ciphertext, currentPosition, AES_BLOCK_SIZE);
                
                currentPosition = nextPosition;
                nextPosition += AES_BLOCK_SIZE;
            }
            
            return ciphertext;
            
        } else {
            logger.fine("Encrypting single block...");
            return encript_AES(plaintext, key);
        }
    }
    
    /**
     * Decrypts ciphertext byte array using CTR mode.
     * @param ciphertext
     * @param key
     * @return
     */
    public byte[] decryptByteArray(byte[] ciphertext, byte[] key) throws Exception {
        logger.fine("ENTRY decryptByteArray ciphertext.length = " + ciphertext.length + " bytes, key.length = " + key.length + " bytes.");
        
        if (ciphertext.length > AES_BLOCK_SIZE) {
            logger.fine("Decrypting via CTR mode...");

            int nblocks = (int)Math.ceil((double)ciphertext.length / AES_BLOCK_SIZE);
            byte[] plaintext = new byte[nblocks * AES_BLOCK_SIZE];
            int currentPosition = 0; 
            int nextPosition = AES_BLOCK_SIZE;
            
            for (int i = 0; i < nblocks; i++) {
                byte[] nextKey = integerToBytes(bytesToInteger(key) + (int)i);
                byte[] plaintextBlock = decript_AES(Arrays.copyOfRange(ciphertext, currentPosition, nextPosition), nextKey);
                
                System.arraycopy(plaintextBlock, 0, plaintext, currentPosition, AES_BLOCK_SIZE);
                
                currentPosition = nextPosition;
                nextPosition += AES_BLOCK_SIZE;
            }
            
            return plaintext;
            
        } else {
            logger.fine("Decrypting single block...");
            return decript_AES(ciphertext, key);
        }
    }
    
    /**
     * 
     * @param key
     * @param hashAlg
     * @param blockSize
     * @return
     */
    public byte[] computeBlockSizedKey(byte[] key, HashAlg hashAlg, int blockSize) throws Exception {
        
        if (key.length >= blockSize) {
            // Keys longer than blockSize are shortened by hashing them
            return computeHash(key, hashAlg);
            
        } else {
            // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
            // Pad key with zeros to make it blockSize bytes long
            return padByteArray(key, blockSize); 
        }
    }
    
    /**
     * Compute HMAC. This algorithm follows the spec: https://www.rfc-editor.org/rfc/rfc2104
     * @param key
     * @param message
     * @param hashAlg
     * @throws Exception
     */
    public byte[] compute_HMAC(byte[] key, byte[] message, HashAlg hashAlg) throws Exception {
        int blockSize = getHashBlockSize(hashAlg);
        int outputSize = getHashOutputSize(hashAlg);
        byte[] blockSizedKey = computeBlockSizedKey(key, hashAlg, blockSize);
        
        byte[] okeyPad = new byte[blockSizedKey.length];
        byte[] ikeyPad = new byte[blockSizedKey.length];
        
        for (int i = 0; i < blockSizedKey.length; i++) {
            okeyPad[i] = (byte) (blockSizedKey[i] ^ 0x5c);
            ikeyPad[i] = (byte) (blockSizedKey[i] ^ 0x36);
        }
        
        // Concat ikeyPad and message
        byte[] iConcat = new byte[ikeyPad.length + message.length];
        System.arraycopy(ikeyPad, 0, iConcat, 0,              ikeyPad.length);
        System.arraycopy(message, 0, iConcat, ikeyPad.length, message.length);
        
        // Hash it
        byte[] iHash = computeHash(iConcat, hashAlg);
        
        // Concat okeyPad and iHash
        byte[] oConcat = new byte[okeyPad.length + iHash.length];
        System.arraycopy(okeyPad, 0, oConcat, 0,              okeyPad.length);
        System.arraycopy(iHash,   0, oConcat, okeyPad.length, iHash.length);
        
        // Hash it
        return computeHash(oConcat, hashAlg);
    }
    
    /**
     * Compute the internal XOR sum for PBKDF2. This corresponds to F (P, S, c, i) in the spec.
     * @param password
     * @param salt
     * @param niterations
     * @param iteration
     * @param hashAlg
     * @return
     * @throws Exception
     */
    public byte[] compute_PBKDF2_XORSUM(byte[] password, byte[] salt, int niterations, int iteration, HashAlg hashAlg) throws Exception {
        
        // Prepare salt || INT(iteration) for U_1
        int sizeOfInt = 4;
        byte[] saltConcatInt = new byte[salt.length + sizeOfInt];
        System.arraycopy(salt, 0, saltConcatInt, 0, salt.length);
        System.arraycopy(ByteBuffer.allocate(sizeOfInt).putInt(iteration).array(), 0, saltConcatInt, salt.length, sizeOfInt);
        
        // Compute U_1
        byte[] current_U = compute_HMAC(password, saltConcatInt, hashAlg); 
        
        // Prepare result
        byte[] result = current_U.clone();
        
        // Loop to compute U_2, U_3, ... , U_c
        for (int i = 1; i < niterations; i++) {
            // Compute U_i
            current_U = compute_HMAC(password, current_U, hashAlg);
            
            // Compute result XOR U_i
            for (int j = 0; j < current_U.length; j++) {
                result[j] = (byte) (result[j] ^ current_U[j]);
            }
        }
        
        return result;
    }
    
    /**
     * Compute PBKDF2 using HMAC. This algorithm follows the spec: https://www.rfc-editor.org/rfc/rfc2898#section-5.2
     * Note, this implementation requires the key size to be a multiple of the underlying hash size.  
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of the derived key.
     * @param hashAlg Hash algorithm to use with HMAC.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2(byte[] password, byte[] salt, int niterations, int dkLen, HashAlg hashAlg) throws Exception {
        logger.fine("ENTRY compute_PBKDF2 " + niterations + " " + dkLen + " " + hashAlg);
        
        if (niterations < 0) {
            throw new Exception("Number of iterations must be greater than zero");
        }
        
        int hLenBytes = getHashOutputSize(hashAlg);
        int hLen = hLenBytes * 8;                   // must be in bits
        
        if (dkLen > (((long)1 << 32) - 1) * hLen) {
            throw new Exception("Derived key length is too long.");
        }
        
        // Force the key length to be a multiple of the hash length. 
        // This is not in the spec, but it simplifies the result.
        if (dkLen % hLen != 0) {
            throw new Exception("Derived key size must be a multiple of " + hLen + " bits.");
        }
        
        int l = (int) Math.ceil(1.0 * dkLen / hLen); // the number of hLen-bit blocks in the derived key
        int r = dkLen - (l - 1) * hLen;              // the number of bits in the last block
        
        logger.info("dkLen = " + dkLen + " hLen = " + hLen + " l = " + l + " r = " + r);
        
        // Prepare byte array for the result
        byte[] result = new byte[l * hLenBytes];
        
        // Compute T_i for blocks 1, 2, ..., l
        for (int i = 1; i <= l; i++) {
            byte[] T_i = compute_PBKDF2_XORSUM(password, salt, niterations, i, hashAlg);
            
            // Concatenate this T_i with the others
            System.arraycopy(T_i, 0, result, (i - 1) * T_i.length, T_i.length);
        }
        
        return result;
    }
    
    /**
     * Compute PBKDF2 using HMAC-SHA256.
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of derived key.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2_SHA256(byte[] password, byte[] salt, int niterations, int dkLen) throws Exception {
        return compute_PBKDF2(password, salt, niterations, dkLen, HashAlg.SHA256);
    }
    
    /**
     * Compute PBKDF2 using HMAC-SHA384.
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of derived key.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2_SHA384(byte[] password, byte[] salt, int niterations, int dkLen) throws Exception {
        return compute_PBKDF2(password, salt, niterations, dkLen, HashAlg.SHA384);
    }
    
    /**
     * Compute PBKDF2 using HMAC-SHA512.
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of derived key.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2_SHA512(byte[] password, byte[] salt, int niterations, int dkLen) throws Exception {
        return compute_PBKDF2(password, salt, niterations, dkLen, HashAlg.SHA512);
    }
    
    /**
     * Decrypt the file metadata.
     * @param metadata The file's metadata
     * @param password The password
     * @return Full, plaintext metadata, including header, secrets, and digests.
     */
    public byte[] decryptMetadata(byte[] metadata, String password) throws Exception {
        logger.info("ENTRY decryptMetadata");

        int nSecretBytes = getEncryptedSecretMetadataSize();
        
        logger.fine("Fetching salt...");
        byte[] salt = getSaltFromMetadata(metadata);
        
        logger.info("Deriving key from password...");
        byte[] derivedkey = compute_PBKDF2(password.getBytes(CHARACTER_SET), salt, N_PBDFK2_ITERATIONS, DERIVED_KEY_LENGTH, PBKDF2_HASH_ALG);
        
        // Only a portion of the metadata is encrypted...
        logger.fine("Decrypting secret metadata section...");
        int startIndex = N_USERNAME_BYTES + N_SALT_BYTES;
        int endIndex = startIndex + nSecretBytes;
        
        byte[] encryptedMetadata = Arrays.copyOfRange(metadata, startIndex, endIndex);
        byte[] secrets = decryptByteArray(encryptedMetadata, derivedkey);
        
        // Copy to new array.
        // Note, the encrypted metadata section had to be padded for the algorithm,
        // so there are likely some 0s we need to trim off. The plaintext secret 
        // section should be HASH + FEK + LENGTH.
        int plaintextMetadataSize = getMetadataSize();
        byte[] result = new byte[plaintextMetadataSize];
        System.arraycopy(metadata, 0, result, 0, startIndex);                               // copy plaintext header
        System.arraycopy(secrets, 0, result, startIndex, getPlaintextSecretMetadataSize()); // copy plaintext secrets, ignoring the extra padding
        System.arraycopy(metadata, 0, result, endIndex, metadata.length - endIndex);        // copy the remaining contents of the metadata
        
        return result;
    }
    
    /**
     * Checks if the password hash matches the stored hash.
     * @param metadata Plaintext metadata.
     * @param password
     * @return true if the hashes match, false otherwise.
     */
    public boolean isCorrectPassword(byte[] metadata, String password) throws Exception {
        
        int hashLength = getHashOutputSize(PASSWORD_HASH_ALG);
        byte[] salt = getSaltFromMetadata(metadata);
        byte[] passwordHash = getPasswordHash(password, new String(salt, CHARACTER_SET));

        byte[] storedPasswordHash = new byte[hashLength];
        System.arraycopy(metadata, N_USERNAME_BYTES + N_SALT_BYTES, storedPasswordHash, 0, hashLength);
        
        if (Arrays.equals(passwordHash, storedPasswordHash)) {
            return true; 
        } else {
            return false;
        }
    }
    
    /**
     * EFS constructor.
     * @param e
     */
    public EFS(Editor e)
    {
        super(e);
                
        try {
            // Initialize logging
            System.setProperty("java.util.logging.SimpleFormatter.format", 
                    "%1$tF %1$tT %4$s %2$s %5$s%6$s%n");
            FileHandler fh = new FileHandler("efs.log");
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setUseParentHandlers(false); // disable console logging
            
            logger.setLevel(Level.FINE);
            logger.getHandlers()[0].setLevel(Level.FINE);
            
        } catch (SecurityException ex) {  
            ex.printStackTrace();  
        } catch (IOException ex) {  
            ex.printStackTrace();
        }
        
        // Set username and password
        //set_username_password();
    }

    /**
     * Create a new file on the filesystem.
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        logger.fine("ENTRY create " + file_name + " " + user_name + " " + password);
        
        dir = new File(file_name);
        
        if (dir.mkdir()) {
            // This is a new file...
            logger.info("Creating new file " + file_name + " for user " + user_name + ".");
            
            try {
                // Metadata will be stored in first physical file.
                File metadataFile = new File(dir, "0");
                
                //################
                // Begin header section...

                byte[] header = new byte[ N_USERNAME_BYTES + N_SALT_BYTES ];
                logger.fine("Username = " + N_USERNAME_BYTES + " bytes, salt = " + N_SALT_BYTES + " bytes, header size = " + header.length + " bytes.");
                
                // Add the username
                if (user_name.length() > N_USERNAME_BYTES) {
                    String msg = "Username longer than " + N_USERNAME_BYTES + " bytes.";
                    logger.severe(msg);
                    throw new Exception(msg);
                }
                System.arraycopy(user_name.getBytes(CHARACTER_SET), 0, header, 0, user_name.length());
                
                // Add the salt
                logger.fine("Generating new salt...");
                String salt = getNewPasswordSalt();
                logger.fine("Salt = " + salt.length() + " bytes.");
                System.arraycopy(salt.getBytes(CHARACTER_SET), 0, header, N_USERNAME_BYTES, N_SALT_BYTES);
                
                //################
                // Begin secret section...
                
                int nSecretBytes = getEncryptedSecretMetadataSize();
                
                logger.fine("Hashing password...");
                byte[] passwordHash = getPasswordHash(password, salt);
                logger.fine("Password hash = " + passwordHash.length + " bytes.");
                
                logger.fine("Generating FEK for this new file...");
                byte[] fek = secureRandomNumber(N_FEK_BYTES);
                logger.fine("FEK = " + fek.length + " bytes.");
                
                byte[] fileLength = integerToBytes(0);  // We are not storing anything yet
                logger.fine("File length = " + fileLength.length + " bytes.");
                
                // Store secret data into temp array so we can encrypt it
                byte[] secretData = new byte[nSecretBytes];
                logger.fine("Secret metadata = " + secretData.length + " bytes.");
                
                System.arraycopy(passwordHash,  0, secretData, 0,                                passwordHash.length);
                System.arraycopy(fek,           0, secretData, passwordHash.length,              fek.length);
                System.arraycopy(fileLength,    0, secretData, passwordHash.length + fek.length, fileLength.length);

                logger.fine("Deriving encryption key from password...");
                byte[] derivedKey = compute_PBKDF2(password.getBytes(CHARACTER_SET), salt.getBytes(CHARACTER_SET), N_PBDFK2_ITERATIONS, DERIVED_KEY_LENGTH, PBKDF2_HASH_ALG);
                logger.fine("Derived key = " + derivedKey.length + " bytes.");
                
                logger.fine("Encrypting secret metadata...");
                byte[] encryptedMetadata = encryptByteArray(secretData, derivedKey);
                logger.fine("Secret metadata = " + encryptedMetadata.length + " bytes.");
                
                //################
                // Begin digest section...
                
                // Metadata digest. We will use the derived key.
                logger.fine("Computing metadata digest...");
                byte[] metadata = new byte[header.length + encryptedMetadata.length];
                System.arraycopy(header, 0, metadata, 0, header.length);
                System.arraycopy(encryptedMetadata, 0, metadata, header.length, encryptedMetadata.length);
                
                byte[] metadataDigest = compute_HMAC(derivedKey, metadata, METADATA_DIGEST_ALG);
                byte[] fileDigest = compute_HMAC(derivedKey, "".getBytes(), FILE_DIGEST_ALG); // digest of empty file
                
                int metadataPlusDigestsLength = header.length + encryptedMetadata.length + metadataDigest.length + fileDigest.length;
                if (metadataPlusDigestsLength > Config.BLOCK_SIZE) {
                    throw new Exception("Metadata section size (" + metadataPlusDigestsLength + ") exceeds physical file size limit (" + Config.BLOCK_SIZE +")");
                }
                
                logger.fine("Metadata digest = " + metadataDigest.length + " bytes, file digest = " + fileDigest.length + " bytes, metadata size = " + metadataPlusDigestsLength + " bytes.");
                
                // Write all data to new array.
                logger.fine("Writing metadata to physical file...");
                 
                byte[] toWrite = new byte[header.length + encryptedMetadata.length + metadataDigest.length + fileDigest.length];
                System.arraycopy(header,            0, toWrite, 0,                                        header.length);
                System.arraycopy(encryptedMetadata, 0, toWrite, header.length,                            encryptedMetadata.length);
                System.arraycopy(metadataDigest,    0, toWrite, header.length + encryptedMetadata.length, metadataDigest.length);
                System.arraycopy(fileDigest,        0, toWrite, header.length + encryptedMetadata.length + metadataDigest.length, fileDigest.length);
    
                save_to_file(toWrite, metadataFile);
                
                logger.info("Successfully created new file " + file_name + " for user " + user_name + ".");
                
            } catch (Exception e) {
                logger.severe("Failed to create new file " + file_name + " for user " + user_name + ": " + e.getMessage());
                
                // Remove the directory
                dir.delete();
                throw e;
            }
        }
    }

    /**
     * Get username from file metadata.
     */
    @Override
    public String findUser(String file_name) throws Exception {
        logger.fine("ENTRY findUser " + file_name);
        
        byte[] metadata = getFileMetadata(file_name);
        String username = null;
        
        if (metadata != null) {
            // Find the first zero byte
            int i;
            for (i = 0; i < metadata.length && metadata[i] != 0; i++) {}
            username = new String(metadata, 0, i, CHARACTER_SET);
            
        } else {
            logger.warning("Failed to retrieve metadata for file " + file_name);
        }
        return username;
    }

    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {
        logger.fine("ENTRY length " + file_name);
        
        logger.fine("Fetching file metadata...");
        byte[] metadata = getFileMetadata(file_name);
        int length = 0;
        
        if (metadata != null) {
            
            logger.info("Getting length of file " + file_name + "...");
            
            byte[] plaintext = decryptMetadata(metadata, password);
            
            logger.info("Checking password...");
            if (!isCorrectPassword(plaintext, password)) {
                logger.info("Password incorrect.");
                throw new PasswordIncorrectException();
            }
            logger.fine("Password correct.");
            
            length = getLengthFromMetadata(plaintext);
            
        } else {
            logger.severe("Failed to retrieve metadata for file " + file_name + ".");
        }
        return length;
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        throw new PasswordIncorrectException();
    	//return null;
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        throw new PasswordIncorrectException();
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        throw new Exception();
    }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        throw new PasswordIncorrectException();
    }
  
}
