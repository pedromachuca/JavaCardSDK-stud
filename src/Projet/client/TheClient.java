package client;

import java.util.Date;
import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;




public class TheClient {



    private final static byte CLA_TEST			           	= (byte)0x90;
    private final static byte INS_TESTDES_ECB_NOPAD_ENC	= (byte)0x28;
    private final static byte INS_TESTDES_ECB_NOPAD_DEC	= (byte)0x29;
    private final static byte INS_DES_ECB_NOPAD_ENC    	= (byte)0x20;
    private final static byte INS_DES_ECB_NOPAD_DEC    	= (byte)0x21;
    private final static byte P1_EMPTY                  = (byte)0x00;
    private final static byte P2_EMPTY                  = (byte)0x00;
    private static final byte CIPHERFILE		            = (byte)0x10;
    private static final byte UNCIPHERFILE		          = (byte)0x11;
    private static final byte CHANGEDESKEY		          = (byte)0x12;
    static final byte DATAMAXSIZE                       = (short)0x02;


    private PassThruCardService servClient = null;

    boolean DISPLAY = true;
    boolean loop = true;

    public static void main( String[] args ) throws InterruptedException {
	    new TheClient();
    }


    public TheClient() {
	    try {
		    SmartCard.start();
		    System.out.print( "Smartcard inserted?... " );

		    CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null);

		    SmartCard sm = SmartCard.waitForCard (cr);

		    if (sm != null) {
			    System.out.println ("got a SmartCard object!\n");
		    } else{
          System.out.println( "did not get a SmartCard object!\n" );
        }

		    this.initNewCard( sm );

		    SmartCard.shutdown();

	    } catch( Exception e ) {
		    System.out.println( "TheClient error: " + e.getMessage() );
				e.printStackTrace();
	    }
	    java.lang.System.exit(0) ;
    }

    private ResponseAPDU sendAPDU(CommandAPDU cmd) {
	    return sendAPDU(cmd, true);
    }

    private ResponseAPDU sendAPDU( CommandAPDU cmd, boolean display ) {
	    ResponseAPDU result = null;
	    try {
		      result = this.servClient.sendCommandAPDU( cmd );
		      if(display)
			       displayAPDU(cmd, result);
	    } catch( Exception e ) {
           	 System.out.println( "Exception caught in sendAPDU: " + e.getMessage() );
           	 java.lang.System.exit( -1 );
      }
	    return result;
    }


    /************************************************
     * *********** BEGINNING OF TOOLS ***************
     * **********************************************/


    private String apdu2string( APDU apdu ) {
	    return removeCR( HexString.hexify( apdu.getBytes() ) );
    }


    public void displayAPDU( APDU apdu ) {
	     System.out.println( removeCR( HexString.hexify( apdu.getBytes() ) ) + "\n" );
    }


    public void displayAPDU( CommandAPDU termCmd, ResponseAPDU cardResp ) {
	     System.out.println( "--> Term: " + removeCR( HexString.hexify( termCmd.getBytes() ) ) );
	      System.out.println( "<-- Card: " + removeCR( HexString.hexify( cardResp.getBytes() ) ) );
    }


    private String removeCR( String string ) {
	    return string.replace( '\n', ' ' );
    }


    /******************************************
     * *********** END OF TOOLS ***************
     * ****************************************/


    private boolean selectApplet() {
	     boolean cardOk = false;
	      try {
	         CommandAPDU cmd = new CommandAPDU( new byte[] {
                  (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
		              (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62,
		              (byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
            } );
            ResponseAPDU resp = this.sendAPDU( cmd );
	          if( this.apdu2string( resp ).equals( "90 00" ) )
		           cardOk = true;
	      } catch(Exception e) {
            System.out.println( "Exception caught in selectApplet: " + e.getMessage() );
            java.lang.System.exit( -1 );
        }
	       return cardOk;
    }


    private void initNewCard( SmartCard card ) {
	     if( card != null )
		     System.out.println( "Smartcard inserted\n" );
	     else {
		       System.out.println( "Did not get a smartcard" );
		       System.exit( -1 );
	     }

	     System.out.println( "ATR: " + HexString.hexify( card.getCardID().getATR() ) + "\n");

	     try {
		       this.servClient = (PassThruCardService)card.getCardService( PassThruCardService.class, true );
	     } catch( Exception e ) {
		       System.out.println( e.getMessage() );
	     }

	     System.out.println("Applet selecting...");
	     if( !this.selectApplet() ) {
		       System.out.println( "Wrong card, no applet to select!\n" );
		       System.exit( 1 );
		       return;
	     } else
		     System.out.println( "Applet selected\n" );
         mainLoop();
	//foo();
    }


    private void testDES_ECB_NOPAD( boolean displayAPDUs ) {
	    testCryptoGeneric(INS_TESTDES_ECB_NOPAD_ENC);
	    testCryptoGeneric(INS_TESTDES_ECB_NOPAD_DEC);
    }


    private void testCryptoGeneric( byte typeINS ) {
	    byte[] t = new byte[4];

	    t[0] = CLA_TEST;
	    t[1] = typeINS;
	    t[2] = P1_EMPTY;
	    t[3] = P2_EMPTY;

      this.sendAPDU(new CommandAPDU( t ));
    }


    private byte[] cipherDES_ECB_NOPAD( byte[] challenge, boolean display ) {
	    return cipherGeneric( INS_DES_ECB_NOPAD_ENC, challenge );
    }


    private byte[] uncipherDES_ECB_NOPAD( byte[] challenge, boolean display ) {
	    return cipherGeneric( INS_DES_ECB_NOPAD_DEC, challenge );
    }


    private byte[] cipherGeneric( byte typeINS, byte[] challenge ) {

		  byte[] result = new byte[challenge.length];

			byte[] cmd_part = {CLA_TEST, typeINS, P1_EMPTY, P2_EMPTY, (byte)challenge.length};

			int size_part = cmd_part.length;
			int totalLength =challenge.length+size_part;
			byte[] cmd_= new byte[totalLength+1];

			System.arraycopy(cmd_part, 0, cmd_, 0, size_part);
			System.arraycopy(challenge, 0, cmd_, size_part, challenge.length);
			cmd_ [totalLength]=(byte)challenge.length;

			CommandAPDU cmd1 = new CommandAPDU( cmd_ );
			ResponseAPDU resp =	this.sendAPDU( cmd1, DISPLAY );

			byte[] result1 =resp.getBytes();
			System.arraycopy(result1, 0, result, 0, challenge.length);

	    // TO COMPLETE
			//forger un apdu de command avec INS set 1er parametre
			//champ data set au 2eme parametre
			//LC=LE
	    return result;
    }

    //
    // private void foo() {
	  //   sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
	  //   byte[] response;
	  //   byte[] unciphered;
	  //   long seed=0;
	  //   java.util.Random r = new java.util.Random( seed );
    //
	  //   byte[] challengeDES = new byte[16]; 		// size%8==0, coz DES key 64bits
    //
	  //   r.nextBytes( challengeDES );
    //
	  //   System.out.println( "**TESTING**");
	  //   testDES_ECB_NOPAD( true );
	  //   System.out.println( "**TESTING**");
    //
	  //   System.out.println("\nchallenge:\n" + encoder.encode(challengeDES) + "\n");
	  //   response = cipherGeneric(INS_DES_ECB_NOPAD_ENC, challengeDES);
	  //   System.out.println("\nciphered is:\n" + encoder.encode(response) + "\n");
	  //   unciphered = cipherGeneric(INS_DES_ECB_NOPAD_DEC, response);
	  //   System.out.print("\nunciphered is:\n" + encoder.encode(unciphered) + "\n");
    // }

    void changeDesKey(){


    }

    void uncipherFile(){

    }

    void cipherFile(){
    //  try{
  			// System.out.println( "Veuillez entrer le nom de fichier a sauvegarder:" );
  			// String filename = readKeyboard();
        //
  			// File file=null;
  			// long fileLength=0;
        //
  			// file = new File(filename);
  			// fileLength = file.length();
        // FileInputStream inputstream = new FileInputStream(file);
        //
        // byte[] result = new byte[DATAMAXSIZE];
        // int compteur = 0;
        // int data = 0;
        //
        // while(((data = inputstream.read(result)) >= 0)&&data==DATAMAXSIZE ){

          // byte[] cmd_part = {CLA_TEST, typeINS, P1_EMPTY, P2_EMPTY, (byte)DATAMAXSIZE};
          //
          // int size_part = cmd_part.length;
          // int totalLength =(int)DATAMAXSIZE+size_part;
          // byte[] cmd_= new byte[totalLength+1];
          //
          // System.arraycopy(cmd_part, 0, cmd_, 0, size_part);
          // System.arraycopy(challenge, 0, cmd_, size_part, challenge.length);
          // cmd_ [totalLength]=(byte)DATAMAXSIZE;
          //
          // CommandAPDU cmd1 = new CommandAPDU( cmd_ );
          // ResponseAPDU resp =	this.sendAPDU( cmd1, DISPLAY );
          //
          // byte[] result1 =resp.getBytes();
          // System.arraycopy(result1, 0, result, 0, challenge.length);
          //
          //
          // System.out.println("nb of read : " + data + " - " + filecontent[0] + " - " + filecontent[1]);
          //
  				// byte[] cmd_part2 = {CLA, WRITEFILETOCARD, (byte)1, (byte)compteur, DATAMAXSIZE};
          //
  				// int sizecmd_part = cmd_part2.length;
  				// totalLength =sizecmd_part+(int)DATAMAXSIZE;
  				// byte[] cmd_5= new byte[totalLength];
          //
  				// System.arraycopy(cmd_part2, 0, cmd_5, 0, sizecmd_part);
  				// System.arraycopy(filecontent, 0, cmd_5, sizecmd_part, (byte)filecontent.length);
          //
  				// CommandAPDU cmd1 = new CommandAPDU( cmd_5 );
  				// this.sendAPDU( cmd1, DISPLAY );
          //
  				// compteur++;

  		//	}

    }

    void exit() {
  		loop = false;
  	}

  	void runAction( int choice ) {
  		switch( choice ) {
  			case 3: changeDesKey(); break;
  			case 2: uncipherFile(); break;
  			case 1: cipherFile(); break;
  			case 0: exit(); break;
  			default: System.out.println( "unknown choice!" );
  		}
  	}


  	String readKeyboard() {
  		String result = null;

  		try {
  			BufferedReader input = new BufferedReader( new InputStreamReader( System.in ) );
  			result = input.readLine();
  		} catch( Exception e ) {}

  		return result;
  	}


  	int readMenuChoice() {
  		int result = 0;

  		try {
  			String choice = readKeyboard();
  			result = Integer.parseInt( choice );
  		} catch( Exception e ) {}

  		System.out.println( "" );

  		return result;
  	}


  	void printMenu() {
  		System.out.println( "" );
  		System.out.println( "3: Change DES key" );
  		System.out.println( "2: Uncipherfile" );
  		System.out.println( "1: Cipher file" );
  		System.out.println( "0: exit" );
  		System.out.print( "--> " );
  	}


  	void mainLoop() {
  		while( loop ) {
  			printMenu();
  			int choice = readMenuChoice();
  			runAction( choice );
  		}
  	}


}
