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

    public void testGetNewPasswordSalt() {
        EFS efs = new EFS(null);
        
        String salt = efs.getNewPasswordSalt();
        assertEquals(salt.length(), 16);
        assertEquals(salt.getBytes(StandardCharsets.US_ASCII).length, 16);
    }
    
    public void testGetPasswordHash() {
        EFS efs = new EFS(null);
        
        String password = "MyP@$$w0rD!23";
        String salt     = efs.getNewPasswordSalt();
        byte[] hash1 = null;
        byte[] hash2 = null;
        
        try {
            hash1 = efs.getPasswordHash(password, salt);
        } catch (Exception e) {
            fail();
        }
        try {
            hash2 = efs.getPasswordHash(password, salt);
        } catch (Exception e) {
            fail();
        }
        
        for (int i = 0; i < hash1.length; i++) {
            assertEquals(hash1[i], hash2[i]);
        }

       assertEquals(hash1.length, 64);
    }
    
    public void testCreate() {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";
        
        try {
            efs.create(filename, "hxs200010", "MyPassword");
        } catch (Exception e) {
            fail(e.getMessage());
        } finally {
            deleteDirectory(filename);            
        }
    }
    
    public void testFindUser() {
        EFS efs = new EFS(null);
        String filename = "testFindUser.txt";
        
        try {
            String result = efs.findUser("someuser");
            assertEquals(result, null);
            
            String username = "hxs200010";
            String password = "MyP@$$W0Rd!23";
            efs.create(filename, username, password);
            
            String foundUser = efs.findUser(filename);
            assertTrue(foundUser.equals(username));
            
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testLength() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testSomething.txt";
        String username = "hxs200010";
        String password = "MyP@$$W0Rd!23";
        int length = -1;
        
        try {
            efs.create(filename, username, password);
            length = efs.length(filename, password);
            
        } catch (Exception e) {
            throw e;
        }
        
        System.out.println(length);
        assertEquals(length, 0);
    }
    
    public void testComputeHmac() {
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
            fail(e.getMessage());
        }
    }
    
    public void testComputePBKDF2() {
        EFS efs = new EFS(null);
        byte[] password = "HereIsMyKey123$%^".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "ThisIsMySalt!23$56&".getBytes(StandardCharsets.US_ASCII);
        int iter = 1000;
        int dkLen = 256;
        
        try {
            EFS.HashAlg alg = EFS.HashAlg.SHA256;
            byte[] result = efs.compute_PBKDF2_SHA256(password, salt, iter, dkLen);
            
            System.out.println(Hex.encodeHexString(result));
            System.out.println(result.length);
            
            assertTrue(Hex.encodeHexString(result).equals("c0409d5527bf10c6d213deb435b6f566da7e4d3b223697ccfca8766eab25ac41"));
            
        } catch (Exception e) {
            System.out.println("Some error: " + e.getMessage());
            fail(e.getMessage());
        }
    }
}
