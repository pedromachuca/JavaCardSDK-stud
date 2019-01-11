//JavaCard 2.1.1

package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class TheApplet extends Applet {


    private final static byte CLA_TEST				= (byte)0x90;

    private static final byte CIPHERFILE      = (byte)0x10;
    private static final byte UNCIPHERFILE	 	= (byte)0x11;
    private static final byte CHANGEDESKEY	 	= (byte)0x12;

    boolean verify = false;

	  static final byte[] theDESKey = new byte[] { (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA };

    // cipher instances
    private Cipher cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;

    // key objects
    private Key secretDESKey, secretDES2Key, secretDES3Key;

    boolean keyDES, DES_ECB_NOPAD;

    protected TheApplet() {
	    initKeyDES();
	    initDES_ECB_NOPAD();

	    this.register();
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

      byte[] buffer = apdu.getBuffer();

      if( selectingApplet() == true )
        return ;

      if( buffer[ISO7816.OFFSET_CLA] != CLA_TEST )
          ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED );

      try { switch( buffer[ISO7816.OFFSET_INS] )
            {
              case CIPHERFILE: if( DES_ECB_NOPAD )
               cipherFile( apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES ); break;
              case UNCIPHERFILE: if( DES_ECB_NOPAD )
                cipherFile( apdu,  cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES ); break;
              case CHANGEDESKEY: if( DES_ECB_NOPAD )
                changeDesKey( apdu ); break;
              default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
    	} catch( Exception e ) {}
    }


    void changeDesKey(APDU apdu){
      apdu.setIncomingAndReceive();
      byte[] buffer = apdu.getBuffer();
      if (buffer[2]==1) {
          if (Util.arrayCompare(theDESKey,(short)0, buffer,(short)5, (short)8) == 0) {
            verify = true;
            buffer[0] = (byte)1;
            apdu.setOutgoingAndSend((short)0,(short)1);
          }
          else{
            verify = false;
          }
      }
      if (buffer[2]==0&&verify==true) {
        ((DESKey)secretDESKey).clearKey();
        Util.arrayCopy(buffer,(byte)5,theDESKey,(short)0,(byte)8);
        initKeyDES();
        initDES_ECB_NOPAD();
        buffer[0] = (byte)1;
        apdu.setOutgoingAndSend((short)0,(short)1);
      }

  }

  void cipherFile(APDU apdu, Cipher cipher, short keyLength){
    apdu.setIncomingAndReceive();
    byte[] buffer = apdu.getBuffer();
    short bigData = (short)(buffer[4]&0xff);
    //buffer[buffer[4]+5] =(buffer[4]&0xff);
    cipher.doFinal( buffer, (short)5, (short)bigData, buffer, (short)5 );
    apdu.setOutgoingAndSend((short)5,(short)bigData);
  }

}
