import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.codec.binary.Hex;


/**
 * Unit test for simple App.
 */
public class EFSTest extends TestCase {
    
    private void deleteDirectory(String dirname) {
        File dir = new File(dirname);
        
        if (dir.exists()) {
            for (File file : dir.listFiles()) {
                file.delete();
            }
            dir.delete();
        }
    }
    
    
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public EFSTest( String testName ) {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite( EFSTest.class );
    }

    public void tearDown() {
        File dir = new File(".");
        File[] files = dir.listFiles((d, name) -> name.startsWith("efs.log"));
        
        for (File file : files) {
            file.delete();
        }
    }
    
    public void testGetNewPasswordSalt() {
        EFS efs = new EFS(null);
        
        String salt = efs.getNewPasswordSalt();
        assertEquals(salt.length(), 16);
        assertEquals(salt.getBytes(StandardCharsets.US_ASCII).length, 16);
    }
    
    public void testGetPasswordHash() throws Exception {
        EFS efs = new EFS(null);
        
        String password = "MyP@$$w0rD!23";
        String salt     = efs.getNewPasswordSalt();
        
        byte[] hash1 = efs.getPasswordHash(password, salt);
        byte[] hash2 = efs.getPasswordHash(password, salt);
        
        assertEquals(hash1.length, 32);
        assertEquals(hash2.length, 32);
        
        for (int i = 0; i < hash1.length; i++) {
            assertEquals(hash1[i], hash2[i]);
        }
        
        byte[] hash3 = efs.getPasswordHash(password+"1", salt);
        byte[] hash4 = efs.getPasswordHash(password, salt+"2");
        
        boolean matches = true;
        for (int i = 0; i < hash1.length; i++) {
            if (hash1[i] != hash3[i]) {
                matches = false;
                break;
            }
        }
        assertFalse(matches);
        
        matches = true;
        for (int i = 0; i < hash1.length; i++) {
            if (hash1[i] != hash4[i]) {
                matches = false;
                break;
            }
        }
        assertFalse(matches);
    }
    
    public void testCreate() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";

        try {
            efs.create(filename, "hxs200010", "MyPassword");
            
            // Check for the directory
            File file = new File(filename);
            assertTrue(file.exists());
            assertTrue(file.isDirectory());
            
            // Check for the physical file
            File phyFile = new File(file, "0");
            assertTrue(phyFile.exists());
            
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);            
        }
    }
    
    public void testFindUser() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFindUser.txt";
        
        try {
            // Find user for non-existent file
            String result = efs.findUser("some-file-that-does-not-exist.txt");
            assertEquals(result, null);
            
            // Now try it on a real file
            String username = "hxs200010";
            String password = "MyP@$$W0Rd!23";
            efs.create(filename, username, password);
            
            String foundUser = efs.findUser(filename);
            assertTrue(foundUser.equals(username));
            
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testLength() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testLength.txt";
        String username = "hxs200010";
        String password = "MyP@$$W0Rd!23";
        
        try {
            // Try on non-existent file
            int length = efs.length(filename, password);
            assertEquals(length, 0);
            
            // Now try real empty file
            efs.create(filename, username, password);
            length = efs.length(filename, password);
            assertEquals(length, 0);
            
            // Next up add some content
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testComputeHmac() throws Exception {
        EFS efs = new EFS(null);
        byte[] key = "key".getBytes(StandardCharsets.US_ASCII);
        byte[] message = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);
        
        try {
            EFS.HashAlg alg = EFS.HashAlg.SHA256;
            byte[] hmacsha256 = efs.compute_HMAC(key, message, alg);
            assertTrue(Hex.encodeHexString(hmacsha256).equals("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
            
            alg = EFS.HashAlg.SHA512;
            byte[] hmacsha512 = efs.compute_HMAC(key, message, alg);
            assertTrue(Hex.encodeHexString(hmacsha512).equals("b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"));
            
        } catch (Exception e) {
            throw e;
        }
    }
    
    public void testComputePBKDF2() throws Exception {
        EFS efs = new EFS(null);
        byte[] password = "HereIsMyKey123$%^".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "ThisIsMySalt!23$56&".getBytes(StandardCharsets.US_ASCII);
        int iter = 1000;
        int dkLen = 256;
        
        try {
            EFS.HashAlg alg = EFS.HashAlg.SHA256;
            byte[] result = efs.compute_PBKDF2_SHA256(password, salt, iter, dkLen);
            
            assertTrue(Hex.encodeHexString(result).equals("c0409d5527bf10c6d213deb435b6f566da7e4d3b223697ccfca8766eab25ac41"));
            
        } catch (Exception e) {
            throw e;
        }
    }
}
