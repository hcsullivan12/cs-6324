import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

/**
 * @author Hunter Sullivan
 * @netid hxs200010
 * @email hunter.sullivan@utdallas.edu
 */
public class EFS extends Utility{
    
    private int MAX_USERNAME_LENGTH = 128;
    private int SALT_LENGTH = 16;
    private int FEK_LENGTH = 16;
    private Charset PASSWORD_CHAR_SET = StandardCharsets.US_ASCII;
    
    /**
     * Generates new password salt.
     * @return Byte array ASCII-encoded.
     */
    public String getNewPasswordSalt() {
        int leftLimit = 33;   // character '!'
        int rightLimit = 126; // letter '~'
        
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(SALT_LENGTH);
        
        for (int i = 0; i < SALT_LENGTH; i++) {
            int randomLimitedInt = leftLimit + (int) 
              (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        return buffer.toString();
    }
    
    /**
     * Get padded username.
     * @param username
     * @return Username string, padded to MAX_USERNAME_LENGTH bytes.
     * @throws Exception
     */
    public String getPaddedUsername(String username) throws Exception {
        if (username.length() > MAX_USERNAME_LENGTH) {
            throw new Exception("Username longer than " + MAX_USERNAME_LENGTH + " bytes.");
        }
        
        String paddedUsername = username;
        for (int i = username.length(); i < MAX_USERNAME_LENGTH; i++) {
            paddedUsername += "\0";
        }
        
        return paddedUsername;
    }
    
    /**
     * Has the password.
     * @param password
     * @param salt
     * @return Hash of the password.
     */
    public byte[] getPasswordHash(String password, String salt) throws Exception {
        String message = password + salt;
        return hash_SHA512(message.getBytes(PASSWORD_CHAR_SET));
    }
    
    public String getHmac(String h, String d) {
        return null;
    }
    
    public void padPhysicalFile(String contents) {
        while (contents.length() < Config.BLOCK_SIZE) {
            contents += '\0';
        }
    }
    
    public byte[] getSaltFromMetadata(byte[] metadata) {
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(metadata, MAX_USERNAME_LENGTH, salt, 0, SALT_LENGTH);
        return salt;
    }
    
    public byte[] getFileMetadata(String filename) throws Exception {
        dir = new File(filename);
        File file = new File(dir, "0");
        
        if (file.exists()) {
            return read_from_file(file);
        } else {
            return null;
        }
    }
    
    public byte[] getKeyFromPassword(String password) {
        return null;
    }
    
    public String padStringToMultipleOf(String message, int base) {
        while (message.length() % base != 0) {
            message += "\0";
        }
        return message;
    }
    
    public byte[] getKeyFromPassword(String password, byte[] passwordHash) {
        byte[] key = new byte[FEK_LENGTH];
        System.arraycopy(passwordHash, 0, key, 0, FEK_LENGTH);
        return key;
    }

    public EFS(Editor e)
    {
        super(e);
        //set_username_password();
    }

   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     *  
     * @todo what if header longer than Config.BLOCK_SIZE
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        dir = new File(file_name);

        if (dir.mkdir()) {
            // This is a new file...
            
            try {
                // Metadata will be stored in first physical file.
                File metadataFile = new File(dir, "0");
                
                // Initialize the entire metadata block
                
                
                // Header = MAX_USERNAME_LENGTH + SALT_LENGTH bytes
                byte[] metadata = new byte[MAX_USERNAME_LENGTH + SALT_LENGTH + ]
                String paddedUsername = getPaddedUsername(user_name);
                String salt = getNewPasswordSalt();
                byte[] header = (paddedUsername + salt).getBytes();
                
                // Secret data
                byte[] passwordHash = getPasswordHash(password, salt);
                byte[] fek = secureRandomNumber(FEK_LENGTH);
                byte[] messageLength = longToBytes(0);
                byte[] secretData = new byte[passwordHash.length + fek.length + messageLength.length];
                System.arraycopy(passwordHash,  0, secretData, 0,                                passwordHash.length);
                System.arraycopy(fek,           0, secretData, passwordHash.length,              fek.length);
                System.arraycopy(messageLength, 0, secretData, passwordHash.length + fek.length, messageLength.length);
                
                // Pad the array to a multiple of FEK_LENGTH
                
                secretData = padArrayToMultipleOf(secretData, FEK_LENGTH);
                
                // Encrypted secret data
                byte[] key = getKeyFromPassword(password, passwordHash);
                byte[] encryptedMetadata = encript_AES(secretData.getBytes(), key);
                
                // Tag
                byte[] hmac = "FIXME".getBytes();
                
                byte[] toWrite = new byte[header.length + encryptedMetadata.length + hmac.length];
                System.arraycopy(header, 0, toWrite, 0, header.length);
                System.arraycopy(encryptedMetadata, 0, toWrite, header.length, encryptedMetadata.length);
                System.arraycopy(hmac, 0, toWrite, header.length + encryptedMetadata.length, hmac.length);
    
                save_to_file(toWrite, metadataFile);
            } catch (Exception e) {
                // Remove the directory
                dir.delete();
                throw e;
            }
        }
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
        byte[] metadata = getFileMetadata(file_name);
        String username = null;
        
        if (metadata != null) {
            // Find the first zero byte
            int i;
            for (i = 0; i < metadata.length && metadata[i] != 0; i++) {}
            username = new String(metadata, 0, i, PASSWORD_CHAR_SET);
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
        byte[] metadata = getFileMetadata(file_name);
        int length = 0;
        
        if (metadata != null) {
            byte[] salt = getSaltFromMetadata(metadata);
            byte[] key = getKeyFromPassword(password);
            
            byte[] plaintext = decript_AES(Arrays.copyOfRange(MAX_USERNAME_LENGTH + SALT_LENGTH, length, length), key);
            byte[] ciphertext = getSecretFromMetadata(metadata);
            byte[] header = decript_AES(ciphertext, key);
            byte[] passwordHash = getPasswordHashFromHeader(header);
            
            if (getPasswordHash(password, byteArray2String(salt)) != passwordHash) {
                throw new PasswordIncorrectException();
            }*/
            
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
