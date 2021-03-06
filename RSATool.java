import java.io.*;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @author Mike Jacobson
 * @version 1.0, October 23, 2013
 */
public class RSATool {
    // OAEP constants
    private final static int K = 128;   // size of RSA modulus in bytes
    private final static int K0 = 16;  // K0 in bytes
    private final static int K1 = 16;  // K1 in bytes

    // RSA key data
    private BigInteger n, phi_n;
    private BigInteger e, d, p, q;
    private BigInteger dp, dq;

    // TODO:  add whatever additional variables that are required to implement
    //    Chinese Remainder decryption as described in Problem 2

    // SecureRandom for OAEP and key generation
    private SecureRandom rnd;

    private boolean debug = false;



    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug)
	    System.out.println("Debug RSA: " + s);
    }


    /**
     * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
     */
    private byte[] G(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}


	byte[] output = new byte[K-K0];
	byte[] input = M;

	int numBytes = 0;
	while (numBytes < K-K0) {
          byte[] hashval = sha1.digest(input);

	  if (numBytes + 20 < K-K0)
	      System.arraycopy(hashval,0,output,numBytes,K0);
	  else
	      System.arraycopy(hashval,0,output,numBytes,K-K0-numBytes);

	  numBytes += 20;
	  input = hashval;
	}

	return output;
    }



    /**
     * H(M) = the 1st K0 bytes of SHA1(M)
     */
    private byte[] H(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}

        byte[] hashval = sha1.digest(M);

	byte[] output = new byte[K0];
	System.arraycopy(hashval,0,output,0,K0);

	return output;
    }



    /**
     * Construct instance for decryption.  Generates both public and private key data.
     *
     * TODO: implement key generation for RSA as per the description in your write-up.
     *   Include whatever extra data is required to implement Chinese Remainder
     *   decryption as described in Problem 2.
     */
    public RSATool(boolean setDebug) {
	// set the debug flag
	debug = setDebug;

	rnd = new SecureRandom();

	// TODO:  include key generation implementation here (remove init of d)
    debug("initiating values");
    initVals();

    BigInteger modInv = e.multiply(d).mod(phi_n);
    debug("checking d times e is congruent to 1 mod phi_n. 1? -> "+modInv);
    
    }

    /**
     * Construct instance for encryption, with n and e supplied as parameters.  No
     * key generation is performed - assuming that only a public key is loaded
     * for encryption.
     */
    public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
	// set the debug flag
	debug = setDebug;
	// initialize random number generator
	rnd = new SecureRandom();
	n = new_n;
	e = new_e;
	d = p = q = null;
    }

    public BigInteger get_n() {	return n; }

    public BigInteger get_e() { return e; }

    /**
     * Encrypts the given byte array using RSA-OAEP.
     *
     * TODO: implement RSA encryption
     *
     * @param plaintext  byte array representing the plaintext
     * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1 bytes
     * @return resulting ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
	debug("In RSA encrypt");

	// make sure plaintext fits into one block
	if (plaintext.length > K-K0-K1)
	    throw new IllegalArgumentException("plaintext longer than one block");

    debug("Start Encrption");
    //return regularRSA(plaintext);
    return encryptRSA_OAEP(plaintext);
    }

    /**
     * Decrypts the given byte array using RSA.
     *
     * TODO:  implement RSA-OAEP decryption using the Chinese Remainder method described in Problem 2
     *
     * @param ciphertext  byte array representing the ciphertext
     * @throw IllegalArgumentException if the ciphertext is not valid
     * @throw IllegalStateException if the class is not initialized for decryption
     * @return resulting plaintexttext
     */
    public byte[] decrypt(byte[] ciphertext) {
	debug("In RSA decrypt");

	// make sure class is initialized for decryption
	if (d == null)
	    throw new IllegalStateException("RSA class not initialized for decryption");
    
    debug("Starting Decrypt");
    //return regularRSADecrypt(ciphertext)
	return decryptRSA_OAEP(ciphertext);
    }

    public byte[] encryptRSA_OAEP(byte[] M)
    {
        BigInteger gr,BIm0k1,s,t,BIC;
        byte[] r,zeros,m0k1,byteS,byteT,C;
        int i = 0;
        do
        {
        r = new byte[K0];
        rnd.nextBytes(r);
        debug("iteration: "+i);

        zeros = new byte[K1];
        Arrays.fill(zeros,(byte) 0);

        m0k1 = new byte[M.length + zeros.length];
        System.arraycopy(M, 0, m0k1, 0, M.length);
        System.arraycopy(zeros, 0, m0k1, M.length, zeros.length);

        BIm0k1 = new BigInteger(m0k1);
        gr = new BigInteger(G(r));

        s = BIm0k1.xor(gr);
        byteS = s.toByteArray();

        t = (new BigInteger(r)).xor(new BigInteger(H(byteS)));
        byteT = t.toByteArray();

        C = new byte[byteS.length + byteT.length];

        System.arraycopy(byteS, 0, C, 0, byteS.length);
        System.arraycopy(byteT, 0, C, byteS.length, byteT.length);
        
        BIC = new BigInteger(C);
        i++;
        }while((BIC.compareTo(n) == 1) || ((new BigInteger(C)).compareTo(BigInteger.ZERO) == -1));
        
        debug("r length = " + r.length + ". With Hex: "+ toHexString(r));        
        debug("s length = " + byteS.length + ". With Hex: "+ toHexString(byteS));    
        debug("t length = " + byteT.length + ". With Hex: "+ toHexString(byteT));       
        debug("C length = " + C.length + ". With Hex: "+ toHexString(C));
        debug("Mod powing and done Encrypt");
        
        C = (BIC.modPow(e,n)).toByteArray();
        return C;
    }

    public byte[] decryptRSA_OAEP(byte[] C)
    {
        BigInteger s,t,u,v,BIm0k1,deC,deM;
        byte[] byteS,byteT,zeros,Vzeros,byteV,newC;


        deM = new BigInteger(CRT(C));   //CRT
        //debug("decrypting using regular RSA");
        //deC = new BigInteger(C);
        //deM = deC.modPow(d,n);       //regular decryption   
            
        C = deM.toByteArray();

        byteS = new byte[K-K0];
        byteT = new byte[K0];
        System.arraycopy(C,0,byteS,0,112);
        System.arraycopy(C,112,byteT,0,K0);

        s = new BigInteger(byteS);
        debug("s length = " + byteS.length + ". With Hex: "+ toHexString(byteS));

        t = new BigInteger(byteT);
        debug("t length = " + byteT.length + ". With Hex: "+ toHexString(byteT));

        u = t.xor(new BigInteger(H(byteS)));
        v = s.xor(new BigInteger(G(u.toByteArray())));
        byteV = v.toByteArray();
        debug("u length = " + u.toByteArray().length + ". With Hex: "+ toHexString(u.toByteArray()));
        debug("v length = " + byteV.length + ". With Hex: "+ toHexString(byteV));

        zeros = new byte[K1];
        Arrays.fill(zeros,(byte) 0);

        Vzeros = new byte[K1];
        System.arraycopy(byteV,byteV.length-K1,Vzeros,0,K1);

        //System.out.println("m0k1: "+ toHexString(m0k1));

        //System.out.println(toHexString(v.toByteArray()));
        //System.out.println(toHexString(zeros));
        //System.out.println(toHexString(Vzeros));

        if(!(Arrays.equals(Vzeros,zeros)))
            throw new IllegalArgumentException("the ciphertext is not valid, REJECT.");

        //System.out.println(toHexString(deM.toByteArray()));

        byte[] finalreturn = new byte[K1];
        System.arraycopy(v.toByteArray(), 0, finalreturn, 0, K1);
        //System.out.println("final: "+toHexString(finalreturn)); 

        return finalreturn;
    }
    
    private byte[] regularRSAEncrypt(byte[] plaintext)
    {
        BigInteger enM = new BigInteger(plaintext);
        BigInteger enC = enM.modPow(e,n); //regular
        return enC.toByteArray();
    }

    private byte[] regularRSADecrypt(byte[] ciphertext)
    {
        BigInteger enC = new BigInteger(ciphertext);
        //BigInteger enM = enC.modPow(d,n); //regular
        BigInteger enM = new BigInteger(CRT(ciphertext));
        return enM.toByteArray();
    }

    private void initVals()
    {
        q = getSGP();
        p = getSGP();
        n = p.multiply(q);
        phi_n = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        //System.out.println(p);
        //System.out.println(q);
        //System.out.println("n: "+n);
        //System.out.println(phi_n);

        e = BigInteger.ONE;

        do
        {
            e = e.add(new BigInteger("2"));
        }
        while(!(e.gcd(phi_n).equals(BigInteger.ONE)));

        d = e.modInverse(phi_n);
        //CRT
        dp = d.mod(p.subtract(BigInteger.ONE));
        dq = d.mod(q.subtract(BigInteger.ONE));
    }

    private BigInteger getSGP()
    {
        BigInteger sgPrime, prime;
        int i =0;
        do
        {
            System.out.println("SGP: "+i);
            prime = new BigInteger(512, 3, rnd);
            sgPrime = (prime.multiply(new BigInteger("2"))).add(BigInteger.ONE);
            i++;
        }
        while(!sgPrime.isProbablePrime(3));

        return sgPrime;
    }
    
    //https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
    private byte[] CRT(byte[] ciphertext)
    {
        BigInteger m1, m2, qinv, h, deM,deC;
        
        debug("decrypting using CRT");
        deC = new BigInteger(ciphertext);        
        m1 = deC.modPow(dp,p);
        m2 = deC.modPow(dq,q);
        qinv = q.modInverse(p);
        h = (qinv.multiply(m1.subtract(m2))).mod(p);
        deM = (m2.add(h.multiply(q))); //CRT
        return deM.toByteArray();
    }

    private String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
	    byte2hex(block[i], buf);
	    if (i < len-1) {
		buf.append(":");
	    }
        }
        return buf.toString();
    }
    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

}
