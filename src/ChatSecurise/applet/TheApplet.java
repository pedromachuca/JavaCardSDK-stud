package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class TheApplet extends Applet {

	private final static byte CLA_TEST                    = (byte)0x90;
	private final static byte INS_RSA_DECRYPT             = (byte)0xA2;
	private final static byte INS_GET_PUBLIC_RSA_KEY      = (byte)0xFE;
	private final static byte INS_DES_ECB_NOPAD_ENC           	= (byte)0x20;
	private final static byte INS_DES_ECB_NOPAD_DEC           	= (byte)0x21;

	// cipher instances
	private Cipher cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;
	// key objects
	private KeyPair keyPair;
	private Key publicRSAKey, privateRSAKey;
	private Key secretDESKey;
	// cipher key length
	private short cipherRSAKeyLength;


	static final byte[] theDESKey =
	new byte[] { (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA };


	// cipher instances
	private Cipher cDES_ECB_NOPAD;

	boolean	keyDES, DES_ECB_NOPAD, DES_CBC_NOPAD;



	// n = modulus
	static final byte[] n = new byte[] {
		(byte)0x90,(byte)0x08,(byte)0x15,(byte)0x32,(byte)0xb3,(byte)0x6a,(byte)0x20,(byte)0x2f,
			(byte)0x40,(byte)0xa7,(byte)0xe8,(byte)0x02,(byte)0xac,(byte)0x5d,(byte)0xec,(byte)0x11,
			(byte)0x1d,(byte)0xfa,(byte)0xf0,(byte)0x6b,(byte)0x1c,(byte)0xb7,(byte)0xa8,(byte)0x39,
			(byte)0x19,(byte)0x50,(byte)0x9c,(byte)0x44,(byte)0xed,(byte)0xa9,(byte)0x51,(byte)0x01,
			(byte)0x0f,(byte)0x11,(byte)0xd6,(byte)0xa3,(byte)0x60,(byte)0xa7,(byte)0x7e,(byte)0x95,
			(byte)0xa2,(byte)0xfa,(byte)0xe0,(byte)0x8d,(byte)0x62,(byte)0x5b,(byte)0xf2,(byte)0x62,
			(byte)0xa2,(byte)0x64,(byte)0xfb,(byte)0x39,(byte)0xb0,(byte)0xf0,(byte)0x6f,(byte)0xa2,
			(byte)0x23,(byte)0xae,(byte)0xbc,(byte)0x5d,(byte)0xd0,(byte)0x1a,(byte)0x68,(byte)0x11,
			(byte)0xa7,(byte)0xc7,(byte)0x1b,(byte)0xda,(byte)0x17,(byte)0xc7,(byte)0x14,(byte)0xab,
			(byte)0x25,(byte)0x92,(byte)0xbf,(byte)0xcc,(byte)0x81,(byte)0x65,(byte)0x7a,(byte)0x08,
			(byte)0x90,(byte)0x59,(byte)0x7f,(byte)0xc4,(byte)0xf9,(byte)0x43,(byte)0x9c,(byte)0xaa,
			(byte)0xbe,(byte)0xe4,(byte)0xf8,(byte)0xfb,(byte)0x03,(byte)0x74,(byte)0x3d,(byte)0xfb,
			(byte)0x59,(byte)0x7a,(byte)0x56,(byte)0xa3,(byte)0x19,(byte)0x66,(byte)0x43,(byte)0x77,
			(byte)0xcc,(byte)0x5a,(byte)0xae,(byte)0x21,(byte)0xf5,(byte)0x20,(byte)0xa1,(byte)0x22,
			(byte)0x8f,(byte)0x3c,(byte)0xdf,(byte)0xd2,(byte)0x03,(byte)0xe9,(byte)0xc2,(byte)0x38,
			(byte)0xe7,(byte)0xd9,(byte)0x38,(byte)0xef,(byte)0x35,(byte)0x82,(byte)0x48,(byte)0xb7,
			(byte)0x85,(byte)0x10,(byte)0x94,(byte)0x52,(byte)0x20,(byte)0xe8,(byte)0xd6,(byte)0x86,
			(byte)0xdb,(byte)0x61,(byte)0x55,(byte)0x90,(byte)0xf9,(byte)0xf7,(byte)0x6b,(byte)0x66,
			(byte)0x7c,(byte)0xa0,(byte)0x67,(byte)0x9e,(byte)0xa1,(byte)0x48,(byte)0xa0,(byte)0xdd,
			(byte)0x58,(byte)0xb7,(byte)0x65,(byte)0x99,(byte)0xc8,(byte)0x19,(byte)0xcc,(byte)0x6f,
			(byte)0x62,(byte)0xd6,(byte)0x5b,(byte)0x9c,(byte)0x4d,(byte)0x48,(byte)0x45,(byte)0x7f,
			(byte)0x13,(byte)0x9d,(byte)0x85,(byte)0x12,(byte)0x8f,(byte)0x62,(byte)0xca,(byte)0x47,
			(byte)0x43,(byte)0xc5,(byte)0xe0,(byte)0x2d,(byte)0x27,(byte)0x78,(byte)0xb7,(byte)0xc3,
			(byte)0x28,(byte)0x5d,(byte)0x49,(byte)0xef,(byte)0x54,(byte)0x16,(byte)0x39,(byte)0xcd,
			(byte)0x66,(byte)0x57,(byte)0x22,(byte)0x72,(byte)0xd0,(byte)0x02,(byte)0x78,(byte)0x51,
			(byte)0x8f,(byte)0x2b,(byte)0xc4,(byte)0x52,(byte)0x9f,(byte)0x9f,(byte)0xf4,(byte)0x38,
			(byte)0x5a,(byte)0xb1,(byte)0x94,(byte)0xa6,(byte)0xe1,(byte)0x6f,(byte)0xf0,(byte)0x44,
			(byte)0x7e,(byte)0xf9,(byte)0xa5,(byte)0xf3,(byte)0xcb,(byte)0x21,(byte)0x2d,(byte)0x2f,
			(byte)0x8c,(byte)0x92,(byte)0x5f,(byte)0x1b,(byte)0x57,(byte)0xf4,(byte)0x5c,(byte)0xfe,
			(byte)0xc1,(byte)0x1c,(byte)0xf5,(byte)0x27,(byte)0x25,(byte)0xbd,(byte)0xed,(byte)0x0c,
			(byte)0x02,(byte)0x5a,(byte)0x15,(byte)0xa0,(byte)0xb7,(byte)0x82,(byte)0x56,(byte)0x24,
			(byte)0xb7,(byte)0x0e,(byte)0x2e,(byte)0xb0,(byte)0xb6,(byte)0x6e,(byte)0x2c,(byte)0xe7,
			(byte)0xa0,(byte)0x0e,(byte)0x92,(byte)0x9c,(byte)0xc7,(byte)0x90,(byte)0xbf,(byte)0x4a,
			(byte)0x67,(byte)0x30,(byte)0xd4,(byte)0x6a,(byte)0x7a,(byte)0x11,(byte)0x38,(byte)0xe9,
			(byte)0x94,(byte)0xbf,(byte)0x94,(byte)0xa9,(byte)0x76,(byte)0xfe,(byte)0x6d,(byte)0xc7,
			(byte)0x46,(byte)0xec,(byte)0xe2,(byte)0xf7,(byte)0xa9,(byte)0xbd,(byte)0x52,(byte)0x89
	};

	// e = public exponent
	static final byte[] e = new byte[] {
		(byte)0x01,(byte)0x00,(byte)0x01
	};

	// d = private exponent
	static final byte[] d = new byte[] {
		(byte)0x69,(byte)0xdf,(byte)0x67,(byte)0x25,(byte)0xa3,(byte)0xb8,(byte)0x88,(byte)0xfb,
			(byte)0xf2,(byte)0xfc,(byte)0xf9,(byte)0x90,(byte)0xad,(byte)0x7f,(byte)0x44,(byte)0xbd,
			(byte)0xb8,(byte)0x59,(byte)0xf3,(byte)0x4b,(byte)0xe9,(byte)0x0a,(byte)0x1f,(byte)0x80,
			(byte)0x09,(byte)0x59,(byte)0xb5,(byte)0xe4,(byte)0xfd,(byte)0x06,(byte)0x0e,(byte)0xe3,
			(byte)0x46,(byte)0x5e,(byte)0x88,(byte)0x76,(byte)0x03,(byte)0xe0,(byte)0x5b,(byte)0x2e,
			(byte)0x47,(byte)0x65,(byte)0x3e,(byte)0x96,(byte)0xef,(byte)0x0c,(byte)0x43,(byte)0x79,
			(byte)0xb9,(byte)0x81,(byte)0x9d,(byte)0x21,(byte)0xe5,(byte)0x2c,(byte)0x78,(byte)0x02,
			(byte)0xa9,(byte)0x54,(byte)0x12,(byte)0x66,(byte)0xab,(byte)0x48,(byte)0x1d,(byte)0xe2,
			(byte)0x6e,(byte)0x1d,(byte)0x7d,(byte)0xb2,(byte)0xce,(byte)0x7a,(byte)0x3f,(byte)0xbb,
			(byte)0x34,(byte)0xf2,(byte)0x46,(byte)0x5f,(byte)0x73,(byte)0x7c,(byte)0xba,(byte)0xf8,
			(byte)0xc1,(byte)0x29,(byte)0x97,(byte)0x85,(byte)0x67,(byte)0xdf,(byte)0x82,(byte)0x87,
			(byte)0x89,(byte)0x61,(byte)0x42,(byte)0xcc,(byte)0x1d,(byte)0xcc,(byte)0x03,(byte)0xce,
			(byte)0x41,(byte)0x7d,(byte)0x8f,(byte)0x25,(byte)0xc1,(byte)0x61,(byte)0xfe,(byte)0x06,
			(byte)0x4f,(byte)0x1a,(byte)0xf2,(byte)0x48,(byte)0x55,(byte)0xd8,(byte)0x6e,(byte)0xc6,
			(byte)0x3f,(byte)0x6d,(byte)0xe1,(byte)0xce,(byte)0xa9,(byte)0x28,(byte)0x9e,(byte)0x03,
			(byte)0x2d,(byte)0x74,(byte)0x59,(byte)0x1c,(byte)0xdb,(byte)0x18,(byte)0xb3,(byte)0x41,
			(byte)0x16,(byte)0xee,(byte)0xdf,(byte)0x91,(byte)0x34,(byte)0x08,(byte)0xcd,(byte)0x08,
			(byte)0x5b,(byte)0x00,(byte)0xf0,(byte)0x7d,(byte)0x57,(byte)0x07,(byte)0x74,(byte)0x64,
			(byte)0x2a,(byte)0x70,(byte)0x7e,(byte)0xcb,(byte)0x51,(byte)0x22,(byte)0xb2,(byte)0x4e,
			(byte)0xd3,(byte)0xbe,(byte)0x6f,(byte)0xed,(byte)0x4c,(byte)0x16,(byte)0x5e,(byte)0x2c,
			(byte)0x88,(byte)0x4d,(byte)0x47,(byte)0x66,(byte)0xad,(byte)0xcf,(byte)0x19,(byte)0xe3,
			(byte)0x27,(byte)0xdf,(byte)0x4b,(byte)0x13,(byte)0x02,(byte)0xd1,(byte)0x54,(byte)0xe9,
			(byte)0x29,(byte)0xa8,(byte)0xa2,(byte)0x0f,(byte)0x03,(byte)0xa8,(byte)0x76,(byte)0x27,
			(byte)0xb9,(byte)0x80,(byte)0x36,(byte)0xc7,(byte)0xe5,(byte)0x4f,(byte)0x35,(byte)0xc0,
			(byte)0x99,(byte)0xc0,(byte)0x21,(byte)0x53,(byte)0x36,(byte)0xcb,(byte)0xd0,(byte)0xb1,
			(byte)0x9c,(byte)0x8a,(byte)0x5f,(byte)0xaa,(byte)0x81,(byte)0x19,(byte)0x71,(byte)0x90,
			(byte)0x7d,(byte)0x03,(byte)0x69,(byte)0xe4,(byte)0x19,(byte)0xa7,(byte)0xdc,(byte)0x50,
			(byte)0x07,(byte)0x08,(byte)0xf5,(byte)0xf9,(byte)0xb3,(byte)0x6b,(byte)0x4f,(byte)0xb1,
			(byte)0x2e,(byte)0x71,(byte)0xad,(byte)0xbc,(byte)0x41,(byte)0x1a,(byte)0x17,(byte)0xf9,
			(byte)0xf1,(byte)0x9a,(byte)0x25,(byte)0xdc,(byte)0x8b,(byte)0xd8,(byte)0xea,(byte)0x5a,
			(byte)0x19,(byte)0x67,(byte)0x18,(byte)0xad,(byte)0x36,(byte)0x01,(byte)0x99,(byte)0x4c,
			(byte)0x85,(byte)0xb7,(byte)0xd5,(byte)0x7c,(byte)0x1b,(byte)0xfb,(byte)0x31,(byte)0xc2,
			(byte)0xd6,(byte)0x66,(byte)0x3a,(byte)0x81,(byte)0x59,(byte)0xd7,(byte)0xb1,(byte)0xdc,
			(byte)0x83,(byte)0xf3,(byte)0xdd,(byte)0xb0,(byte)0x27,(byte)0x7a,(byte)0x53,(byte)0x27,
			(byte)0xb5,(byte)0x02,(byte)0x7b,(byte)0xec,(byte)0x22,(byte)0xe5,(byte)0xc8,(byte)0x5d,
			(byte)0xef,(byte)0x88,(byte)0x70,(byte)0x15,(byte)0xa4,(byte)0x6f,(byte)0x8c,(byte)0x8d
	};

	// cipher input data
	static final byte[] inC = new byte[] {
		(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x04,(byte)0x05,(byte)0x06,(byte)0x07,(byte)0x08,
			(byte)0x09,(byte)0x0A,(byte)0x0B,(byte)0x0C,(byte)0x0D,(byte)0x0E,(byte)0x0F,(byte)0x10,
			(byte)0x11,(byte)0x12,(byte)0x13,(byte)0x14,(byte)0x15,(byte)0x16,(byte)0x17,(byte)0x18,
			(byte)0x19,(byte)0x1A,(byte)0x1B,(byte)0x1C,(byte)0x1D,(byte)0x1E,(byte)0x1F,(byte)0x20,
			(byte)0x21,(byte)0x22,(byte)0x23,(byte)0x24,(byte)0x25,(byte)0x26,(byte)0x27,(byte)0x28,
			(byte)0x29,(byte)0x2A,(byte)0x2B,(byte)0x2C,(byte)0x2D,(byte)0x2E,(byte)0x2F,(byte)0x30,
			(byte)0x31,(byte)0x32,(byte)0x33,(byte)0x34,(byte)0x35,(byte)0x36,(byte)0x37,(byte)0x38,
			(byte)0x39,(byte)0x3A,(byte)0x3B,(byte)0x3C,(byte)0x3D,(byte)0x3E,(byte)0x3F,(byte)0x40,
			(byte)0x41,(byte)0x42,(byte)0x43,(byte)0x44,(byte)0x45,(byte)0x46,(byte)0x47,(byte)0x48,
			(byte)0x49,(byte)0x4A,(byte)0x4B,(byte)0x4C,(byte)0x4D,(byte)0x4E,(byte)0x4F,(byte)0x50,
			(byte)0x51,(byte)0x52,(byte)0x53,(byte)0x54,(byte)0x55,(byte)0x56,(byte)0x57,(byte)0x58,
			(byte)0x59,(byte)0x5A,(byte)0x5B,(byte)0x5C,(byte)0x5D,(byte)0x5E,(byte)0x5F,(byte)0x60,
			(byte)0x61,(byte)0x62,(byte)0x63,(byte)0x64,(byte)0x65,(byte)0x66,(byte)0x67,(byte)0x68,
			(byte)0x69,(byte)0x6A,(byte)0x6B,(byte)0x6C,(byte)0x6D,(byte)0x6E,(byte)0x6F,(byte)0x70,
			(byte)0x71,(byte)0x72,(byte)0x73,(byte)0x74,(byte)0x75,(byte)0x76,(byte)0x77,(byte)0x78,
			(byte)0x79,(byte)0x7A,(byte)0x7B,(byte)0x7C,(byte)0x7D,(byte)0x7E,(byte)0x7F,(byte)0x01
	};

	// RSA-NO-PAD Encryption result
	static final byte[] cRSAPublicEncResult = new byte[] {
		(byte)0x69,(byte)0xF5,(byte)0x49,(byte)0x95,(byte)0x8D,(byte)0x9D,(byte)0x05,(byte)0x1E,
			(byte)0xFD,(byte)0x78,(byte)0xE2,(byte)0x8E,(byte)0xDF,(byte)0x2A,(byte)0x08,(byte)0xA1,
			(byte)0x3C,(byte)0x6B,(byte)0x77,(byte)0x98,(byte)0x55,(byte)0x18,(byte)0x5F,(byte)0xC9,
			(byte)0x37,(byte)0xEC,(byte)0x07,(byte)0x3A,(byte)0xB1,(byte)0x32,(byte)0x19,(byte)0x5F,
			(byte)0xFC,(byte)0x97,(byte)0xE1,(byte)0xB3,(byte)0xD4,(byte)0xDC,(byte)0xF7,(byte)0xD9,
			(byte)0x38,(byte)0xB5,(byte)0x7A,(byte)0x4A,(byte)0xDC,(byte)0xC9,(byte)0x46,(byte)0x7B,
			(byte)0xDB,(byte)0x39,(byte)0xE4,(byte)0x2C,(byte)0x63,(byte)0xBA,(byte)0x99,(byte)0x29,
			(byte)0x1C,(byte)0x60,(byte)0x58,(byte)0x71,(byte)0x5B,(byte)0x12,(byte)0xCE,(byte)0xE9,
			(byte)0x81,(byte)0x25,(byte)0x7C,(byte)0x8A,(byte)0x38,(byte)0x08,(byte)0x8C,(byte)0x39,
			(byte)0xD0,(byte)0xA1,(byte)0xFC,(byte)0xBF,(byte)0xB7,(byte)0x04,(byte)0x34,(byte)0x6C,
			(byte)0x93,(byte)0x0D,(byte)0x38,(byte)0x3C,(byte)0xC9,(byte)0x42,(byte)0x38,(byte)0x6E,
			(byte)0x0A,(byte)0x38,(byte)0x74,(byte)0xC4,(byte)0x71,(byte)0xA8,(byte)0x34,(byte)0x60,
			(byte)0x31,(byte)0x09,(byte)0xCE,(byte)0xC3,(byte)0xBE,(byte)0x82,(byte)0x69,(byte)0x07,
			(byte)0x5B,(byte)0xC1,(byte)0xD8,(byte)0x63,(byte)0x04,(byte)0x68,(byte)0x16,(byte)0xB7,
			(byte)0x49,(byte)0x7F,(byte)0xE1,(byte)0xF0,(byte)0x6A,(byte)0xEB,(byte)0xA2,(byte)0x81,
			(byte)0x1D,(byte)0x36,(byte)0xDC,(byte)0xF4,(byte)0x02,(byte)0xED,(byte)0xB3,(byte)0xF5,
			(byte)0x39,(byte)0x41,(byte)0x60,(byte)0xF4,(byte)0x38,(byte)0x19,(byte)0xEF,(byte)0x6B,
			(byte)0xC6,(byte)0x58,(byte)0x65,(byte)0x49,(byte)0x68,(byte)0x5B,(byte)0x93,(byte)0x3A,
			(byte)0xE1,(byte)0x4D,(byte)0x57,(byte)0x69,(byte)0x10,(byte)0x4C,(byte)0xF4,(byte)0x8A,
			(byte)0x13,(byte)0x84,(byte)0x0F,(byte)0x8B,(byte)0x7D,(byte)0x9B,(byte)0x76,(byte)0xB2,
			(byte)0xCD,(byte)0xB0,(byte)0x46,(byte)0x2E,(byte)0xD5,(byte)0x4A,(byte)0xB0,(byte)0x15,
			(byte)0xE1,(byte)0x1A,(byte)0xBC,(byte)0x53,(byte)0xF8,(byte)0x50,(byte)0x29,(byte)0xDE,
			(byte)0xAD,(byte)0xE7,(byte)0xA3,(byte)0x79,(byte)0xC5,(byte)0x43,(byte)0xE9,(byte)0x58,
			(byte)0x38,(byte)0xEF,(byte)0x37,(byte)0x59,(byte)0x4A,(byte)0xE8,(byte)0x68,(byte)0xA9,
			(byte)0x1E,(byte)0x29,(byte)0xFF,(byte)0xBD,(byte)0x25,(byte)0xF7,(byte)0x74,(byte)0xAA,
			(byte)0xD0,(byte)0x2D,(byte)0xDC,(byte)0x47,(byte)0x1E,(byte)0x60,(byte)0xE4,(byte)0x0F,
			(byte)0x20,(byte)0xDD,(byte)0x5A,(byte)0xFD,(byte)0xF2,(byte)0x42,(byte)0x8C,(byte)0xCA,
			(byte)0x39,(byte)0xCF,(byte)0x89,(byte)0x33,(byte)0x7B,(byte)0x87,(byte)0x27,(byte)0x1C,
			(byte)0x29,(byte)0x67,(byte)0x26,(byte)0x7D,(byte)0x0E,(byte)0xAB,(byte)0xD1,(byte)0x6A,
			(byte)0x9A,(byte)0x10,(byte)0xB9,(byte)0x81,(byte)0xF7,(byte)0x85,(byte)0x37,(byte)0xE3,
			(byte)0x91,(byte)0x17,(byte)0x99,(byte)0xC5,(byte)0x17,(byte)0x9B,(byte)0x65,(byte)0xAF,
			(byte)0x65,(byte)0x14,(byte)0x30,(byte)0x42,(byte)0x00,(byte)0x4E,(byte)0xD5,(byte)0x64,
			(byte)0xFD,(byte)0xAB,(byte)0x08,(byte)0x03,(byte)0x48,(byte)0x40,(byte)0x73,(byte)0xDB,
			(byte)0x19,(byte)0xE7,(byte)0x1D,(byte)0x21,(byte)0x19,(byte)0x8A,(byte)0xD2,(byte)0x0A,
			(byte)0x3D,(byte)0xB8,(byte)0xC1,(byte)0x2B,(byte)0xEB,(byte)0x93,(byte)0xA0,(byte)0x6D,
			(byte)0x90,(byte)0x04,(byte)0x3B,(byte)0x15,(byte)0x51,(byte)0xBF,(byte)0x9C,(byte)0x63
	};


	protected TheApplet() {
		initKeyDES();
	  initDES_ECB_NOPAD();

		publicRSAKey = privateRSAKey = null;
		cRSA_NO_PAD = null;

		cipherRSAKeyLength = KeyBuilder.LENGTH_RSA_1024;
		// build RSA pattern keys
		publicRSAKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, cipherRSAKeyLength, true);
		privateRSAKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, cipherRSAKeyLength, false);
		// initialize RSA public key
		((RSAPublicKey)publicRSAKey).setModulus(n, (short)0, (short)(cipherRSAKeyLength/8));
		((RSAPublicKey)publicRSAKey).setExponent(e, (short)0, (short)e.length);
		// initialize RSA private key
		((RSAPrivateKey)privateRSAKey).setModulus(n, (short)0, (short)(cipherRSAKeyLength/8));
		((RSAPrivateKey)privateRSAKey).setExponent(d, (short)0, (short)(cipherRSAKeyLength/8));
		// get cipher RSA instance
		cRSA_NO_PAD = Cipher.getInstance((byte)0x0C, false );

		register();

	}

	private void initKeyDES() {
		try {
			secretDESKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
			((DESKey)secretDESKey).setKey(theDESKey,(short)0);
			keyDES = true;
		} catch( Exception e ) {
			keyDES = false;
		}
	}


	private void initDES_ECB_NOPAD() {
		if( keyDES ) try {
			cDES_ECB_NOPAD_enc = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);//enc ->utilise des en mode ecb no pad
			cDES_ECB_NOPAD_dec = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
			cDES_ECB_NOPAD_enc.init( secretDESKey, Cipher.MODE_ENCRYPT );
			cDES_ECB_NOPAD_dec.init( secretDESKey, Cipher.MODE_DECRYPT );
			DES_ECB_NOPAD = true;
		} catch( Exception e ) {
			DES_ECB_NOPAD = false;
		}
	}


	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new TheApplet();
	}


	public void process(APDU apdu) throws ISOException {
		if (selectingApplet())
			return ;

		byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] != CLA_TEST)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		switch(buffer[ISO7816.OFFSET_INS]) {
			// case INS_GENERATE_RSA_KEY: generateRSAKey(); break;
			// case INS_RSA_ENCRYPT: RSAEncrypt(apdu); break;
			case INS_RSA_DECRYPT: RSADecrypt(apdu); break;
			case INS_GET_PUBLIC_RSA_KEY: getPublicRSAKey(apdu); break;
			case INS_DES_ECB_NOPAD_ENC: if( DES_ECB_NOPAD )
				cipherGeneric( apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES ); break;
			case INS_DES_ECB_NOPAD_DEC: if( DES_ECB_NOPAD )
				cipherGeneric( apdu, cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES  ); break;
			default: ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
	}

	 void cipherGeneric( APDU apdu, Cipher cipher, short keyLength ) {
    apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
    cipher.doFinal( buffer, (short)5, (short)buffer[4], buffer, (short)5 );
    apdu.setOutgoingAndSend((short)5,(short)buffer[4]);
		// Write the method ciphering/unciphering data from the computer.
		// The result is sent back to the computer.
    //buffer[4] -> LC nbre d'octet a traiter
	}

	// RSA Decrypt (with private key)
	void RSADecrypt(APDU apdu) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		// initialize the algorithm with default key
		cRSA_NO_PAD.init( privateRSAKey, Cipher.MODE_DECRYPT );
		short dataLen = (short)(128);
		cRSA_NO_PAD.doFinal( buffer, (short)5, (short)dataLen, buffer, (short)0 );
		// send difference
		apdu.setOutgoingAndSend((short)0,(short)dataLen);
	}


	void getPublicRSAKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// get the element type and length
		byte keyElement = (byte)(buffer[ISO7816.OFFSET_P2] & 0xFF);
		// check correct type (modulus or exponent)
		if((keyElement != 0x00) && (keyElement != 0x01))
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		// check elements request
		if(keyElement == 0) {
			// retrieve modulus
			buffer[0] = (byte)((RSAPublicKey)publicRSAKey).getModulus(buffer, (short)1);
		} else
			// retrieve exponent
			buffer[0] = (byte)((RSAPublicKey)publicRSAKey).getExponent(buffer, (short)1);
		// send the key element
		apdu.setOutgoingAndSend((short)0, (short)((buffer[0] & 0xFF) + 1));
	}
}
