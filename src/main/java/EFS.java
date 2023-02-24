import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

/**
 * @author Hunter Sullivan
 * @netid hxs200010
 * @email hunter.sullivan@utdallas.edu
 */
public class EFS extends Utility{
    
    private int N_USERNAME_BYTES = 128;
    private int N_SALT_BYTES = 16;
    private int N_FEK_BYTES = 16;
    private int N_PASSWORD_HASH_BYTES = 64;
    private int N_LENGTH_BYTES = 4;
    private int ENCRYPTION_ALG_BLOCK_SIZE = 128;
    private int N_SECRETS_BYTES = 0;
    private Charset CHARACTER_SET = StandardCharsets.US_ASCII;
    private ByteBuffer intByteBuffer = ByteBuffer.allocate(Integer.BYTES);
    private Logger logger = Logger.getLogger(EFS.class.getName()); 
    
    public static enum HashAlg {
        SHA256,
        SHA384,
        SHA512
    }
    
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
        if (N_PASSWORD_HASH_BYTES == 32) {
            return hash_SHA256((password + salt).getBytes(CHARACTER_SET));
        } else if (N_PASSWORD_HASH_BYTES == 64) {
            return hash_SHA512(message.getBytes(CHARACTER_SET));
        } else {
            throw new Exception("Password hash size " + N_PASSWORD_HASH_BYTES + " not implemented.");
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
     * Fetch file metadata.
     * @param filename
     * @return Metadata as byte array.
     * @throws Exception
     */
    public byte[] getFileMetadata(String filename) throws Exception {
        dir = new File(filename);
        File file = new File(dir, "0");
        
        if (file.exists()) {
            return read_from_file(file);
        } else {
            return null;
        }
    }
    
    /**
     * Derive key from password. Note, the key must be a certain length.
     * @param password
     * @param passwordHash
     * @return The key as a byte array.
     */
    public byte[] getKeyFromPassword(String password, byte[] passwordHash) {
        byte[] key = new byte[N_FEK_BYTES];
        System.arraycopy(passwordHash, 0, key, 0, N_FEK_BYTES);
        return key;
    }
    
    /**
     * Encrypts plaintext byte array using CTR mode.
     * @param plaintext
     * @param key
     * @return Ciphertext byte array.
     */
    public byte[] encryptByteArray(byte[] plaintext, byte[] key) throws Exception {
        
        if (plaintext.length > ENCRYPTION_ALG_BLOCK_SIZE) {
            
            int nblocks = (int)Math.ceil((double)plaintext.length / ENCRYPTION_ALG_BLOCK_SIZE);
            byte[] ciphertext = new byte[nblocks * ENCRYPTION_ALG_BLOCK_SIZE];
            int currentPosition = 0; 
            int nextPosition = ENCRYPTION_ALG_BLOCK_SIZE;
            
            for (int i = 0; i < nblocks; i++) {
                byte[] nextKey = integerToBytes(bytesToInteger(key) + (int)i);
                byte[] ciphertextBlock = encript_AES(Arrays.copyOfRange(plaintext, currentPosition, nextPosition), nextKey);
                
                System.arraycopy(ciphertextBlock, 0, ciphertext, currentPosition, ENCRYPTION_ALG_BLOCK_SIZE);
                
                currentPosition = nextPosition;
                nextPosition += ENCRYPTION_ALG_BLOCK_SIZE;
            }
            
            return ciphertext;
            
        } else {
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
        
        if (ciphertext.length > ENCRYPTION_ALG_BLOCK_SIZE) {

            int nblocks = (int)Math.ceil((double)ciphertext.length / ENCRYPTION_ALG_BLOCK_SIZE);
            byte[] plaintext = new byte[nblocks * ENCRYPTION_ALG_BLOCK_SIZE];
            int currentPosition = 0; 
            int nextPosition = ENCRYPTION_ALG_BLOCK_SIZE;
            
            for (int i = 0; i < nblocks; i++) {
                byte[] nextKey = integerToBytes(bytesToInteger(key) + (int)i);
                byte[] plaintextBlock = decript_AES(Arrays.copyOfRange(ciphertext, currentPosition, nextPosition), nextKey);
                
                System.arraycopy(plaintextBlock, 0, plaintext, currentPosition, ENCRYPTION_ALG_BLOCK_SIZE);
                
                currentPosition = nextPosition;
                nextPosition += ENCRYPTION_ALG_BLOCK_SIZE;
            }
            
            return plaintext;
            
        } else {
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
        logger.fine("ENTRY compute_HMAC " + key.length + " " + message.length + " " + hashAlg);
        int blockSize = getHashBlockSize(hashAlg);
        int outputSize = getHashOutputSize(hashAlg);
        byte[] blockSizedKey = computeBlockSizedKey(key, hashAlg, blockSize);
        
        logger.fine("HashAlg = " + hashAlg + " block size = " + blockSize + " outputSize = " + outputSize);
        logger.fine("BlockSizedKey size = " + blockSizedKey.length);
        
        byte[] okeyPad = new byte[blockSizedKey.length];
        byte[] ikeyPad = new byte[blockSizedKey.length];
        
        for (int i = 0; i < blockSizedKey.length; i++) {
            okeyPad[i] = (byte) (blockSizedKey[i] ^ 0x5c);
            ikeyPad[i] = (byte) (blockSizedKey[i] ^ 0x36);
        }
        
        // Concat ikeyPad and message
        logger.fine("Concatenating ikeyPad and message...");
        byte[] iConcat = new byte[ikeyPad.length + message.length];
        System.arraycopy(ikeyPad, 0, iConcat, 0,              ikeyPad.length);
        System.arraycopy(message, 0, iConcat, ikeyPad.length, message.length);
        
        // Hash it
        logger.fine("Hashing it...");
        byte[] iHash = computeHash(iConcat, hashAlg);
        
        // Concat okeyPad and iHash
        logger.fine("Concatenating ikeyPad and message...");
        byte[] oConcat = new byte[okeyPad.length + iHash.length];
        System.arraycopy(okeyPad, 0, oConcat, 0,              okeyPad.length);
        System.arraycopy(iHash,   0, oConcat, okeyPad.length, iHash.length);
        
        // Hash it
        logger.fine("Hashing it...");
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
        
        if (dkLen % hLen != 0) {
            throw new Exception("Derived key size must be a multiple of " + hLen + " bits.");
        }
        
        int l = (int) Math.ceil(1.0 * dkLen / hLen); // the number of hLen-bit blocks in the derived key
        int r = dkLen - (l - 1) * hLen;              // the number of bits in the last block
        
        logger.info("dkLen = " + dkLen + " hLen = " + hLen + " l = " + l + " r = " + r);
        
        // Prepare byte array for the result
        byte[] result = new byte[l * hLenBytes];
        
        // Compute T_i for blocks 1, 2, ..., l
        System.out.println("Starting loop...");
        for (int i = 1; i <= l; i++) {
            System.out.println("Computing " + i + "th XOR sum...");
            byte[] T_i = compute_PBKDF2_XORSUM(password, salt, niterations, i, hashAlg);
            System.out.println("Finsihed...");
            
            // Concatenate this T_i with the others
            System.out.println("T_i size = " + T_i.length + " result size = " + result.length);
            System.arraycopy(T_i, 0, result, (i - 1) * T_i.length, T_i.length);
            System.out.println("Hey there");
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
     * EFS constructor.
     * @param e
     */
    public EFS(Editor e)
    {
        super(e);
        
        // Set log level and log to console
        logger.setLevel(Level.INFO);
        logger.addHandler(new StreamHandler(System.out, new SimpleFormatter()));
        logger.getHandlers()[0].setLevel(Level.INFO);
        
        // Set username and password
        //set_username_password();
        
        // Determine size of the secret data section and cache it, needs to be multiple of N_FEK_BYTES.
        N_SECRETS_BYTES = N_PASSWORD_HASH_BYTES + N_FEK_BYTES + N_LENGTH_BYTES;
        
        while (N_SECRETS_BYTES % N_FEK_BYTES != 0) {
            N_SECRETS_BYTES += 1;
        }
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
                
                // Add the username
                if (user_name.length() > N_USERNAME_BYTES) {
                    throw new Exception("Username longer than " + N_USERNAME_BYTES + " bytes.");
                }
                System.arraycopy(user_name.getBytes(CHARACTER_SET), 0, header, 0, user_name.length());
                
                // Add the salt
                logger.fine("Generating new salt...");
                String salt = getNewPasswordSalt();
                System.arraycopy(salt.getBytes(CHARACTER_SET), 0, header, N_USERNAME_BYTES, N_SALT_BYTES);
                
                //################
                // Begin secret section...

                logger.fine("Hashing password...");
                byte[] passwordHash = getPasswordHash(password, salt);
                logger.fine("Generating FEK for this new file...");
                byte[] fek = secureRandomNumber(N_FEK_BYTES);
                byte[] fileLength = integerToBytes(0);  // We are not storing anything yet
                
                // Store secret data into temp array so we can encrypt it
                byte[] secretData = new byte[N_SECRETS_BYTES];
                System.arraycopy(passwordHash,  0, secretData, 0,                                passwordHash.length);
                System.arraycopy(fek,           0, secretData, passwordHash.length,              fek.length);
                System.arraycopy(fileLength,    0, secretData, passwordHash.length + fek.length, fileLength.length);
                
                // Encrypted secret data
                logger.fine("Encrypting secret metadata...");
                byte[] derivedKey = getKeyFromPassword(password, passwordHash);
                byte[] encryptedMetadata = encryptByteArray(secretData, derivedKey);
                
                //################
                // Begin digest section...
                
                // Tag
                byte[] hmac = "FIXME".getBytes();
                
                // Write all data to new array
                logger.fine("Writing metadata to physical file...");
                byte[] toWrite = new byte[header.length + encryptedMetadata.length + hmac.length];
                System.arraycopy(header,            0, toWrite, 0,                                        header.length);
                System.arraycopy(encryptedMetadata, 0, toWrite, header.length,                            encryptedMetadata.length);
                System.arraycopy(hmac,              0, toWrite, header.length + encryptedMetadata.length, hmac.length);
    
                save_to_file(toWrite, metadataFile);
                
                logger.fine("Finished creating new file " + file_name + " for user " + user_name + ".");
                
            } catch (Exception e) {
                logger.warning("Failed to create new file " + file_name + " for user " + user_name);
                
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
        logger.fine("ENTRY length " + file_name + " " + password);
        
        byte[] metadata = getFileMetadata(file_name);
        int length = 0;
        
        if (metadata != null) {
            
            // Fetch salt and derive the AES key from the given password.
            byte[] salt = getSaltFromMetadata(metadata);
            byte[] passwordHash = getPasswordHash(password, new String(salt, CHARACTER_SET));
            byte[] key = getKeyFromPassword(password, passwordHash);
            
            // Attempt to decrypt the secret metadata...
            byte[] plaintext = decryptByteArray(Arrays.copyOfRange(metadata, N_USERNAME_BYTES + N_SALT_BYTES, N_SECRETS_BYTES), key);
            byte[] storedPasswordHash = Arrays.copyOfRange(plaintext, 0, N_PASSWORD_HASH_BYTES);
            
            if (!Arrays.equals(passwordHash, passwordHash)) {
                throw new PasswordIncorrectException();
            }
            
            // The password is correct...
            length = bytesToInteger(Arrays.copyOfRange(plaintext, N_PASSWORD_HASH_BYTES + N_FEK_BYTES, plaintext.length));
            
        } else {
            logger.warning("Failed to retrieve metadata for file " + file_name);
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
        throw new PasswordIncorrectException();
    	//return true;
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
