package client;

import java.util.Date;
import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;




public class TheClient {



    private final static byte CLA_TEST			           	= (byte)0x90;
    // private final static byte INS_TESTDES_ECB_NOPAD_ENC	= (byte)0x28;
    // private final static byte INS_TESTDES_ECB_NOPAD_DEC	= (byte)0x29;
    // private final static byte INS_DES_ECB_NOPAD_ENC    	= (byte)0x20;
    // private final static byte INS_DES_ECB_NOPAD_DEC    	= (byte)0x21;
    private final static byte P1_EMPTY                  = (byte)0x00;
    private final static byte P2_EMPTY                  = (byte)0x00;
    private static final byte CIPHERFILE		            = (byte)0x10;
    private static final byte UNCIPHERFILE		          = (byte)0x11;
    private static final byte CHANGEDESKEY		          = (byte)0x12;
    static final byte DATAMAXSIZE                       = (short)0x08;


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
    }


    void changeDesKey(){

      System.out.println( "Veuillez entrer l'ancienne clef DES:" );
      String StringDesKey = readKeyboard();
      System.out.println( "Des key : "+StringDesKey);
      //DES KEY TO CHANGE : 0xCA,0xCA,0xCA,0xCA,0xCA,0xCA,0xCA,0xCA

      byte[] byteDesKey = StringDesKey.getBytes();
      System.out.println( "Des key : "+HexString.hexify(byteDesKey));

      //byte[] cmd_part = {CLA_TEST, CHANGEDESKEY, P1_EMPTY, P2_EMPTY, (byte)8};


    }

    void cipherFile(byte typeINS){

      try{
        if (typeINS==CIPHERFILE) {
           System.out.println( "Veuillez entrer le nom de fichier a chiffrer:" );
        }else{
          System.out.println( "Veuillez entrer le nom de fichier a dechiffrer:" );
        }

  			 String filename = readKeyboard();

  			 File file=null;
  			 long fileLength=0;
         int totalLength = 0;
  			 file = new File(filename);
  			 fileLength = file.length();
         int leftpadding = (int)DATAMAXSIZE -((int)fileLength%DATAMAXSIZE);

         if (typeINS==UNCIPHERFILE){
           totalLength = (int)fileLength;
         }
         else{
            totalLength =(int)fileLength+leftpadding;
         }
         FileInputStream inputstream = new FileInputStream(file);

         byte[] result = new byte[DATAMAXSIZE];
         int compteur = 0;
         int data = 0;
         String ciphered = "";

         byte[] result2 = new byte [totalLength];

         while(((data = inputstream.read(result)) >= 0) ){

           byte[] cmd_part = {CLA_TEST, typeINS, P1_EMPTY, P2_EMPTY, (byte)DATAMAXSIZE};

           int size_part = cmd_part.length;

           totalLength =(int)DATAMAXSIZE+size_part;
           byte[] cmd_= new byte[totalLength+1];

           System.arraycopy(cmd_part, 0, cmd_, 0, size_part);
           System.out.println("data "+data);
           System.out.println("leftpadding "+leftpadding);

           if (typeINS==CIPHERFILE&&data!=DATAMAXSIZE) {
             for (int i=DATAMAXSIZE-leftpadding;i<DATAMAXSIZE ;i++ ) {
                 result[i]=(byte)leftpadding;
               }
               for(int i=0; i<result.length;i++)
                 System.out.println("padding "+HexString.hexify( result[i] ));
           }

           System.arraycopy(result, 0, cmd_, size_part, (int)DATAMAXSIZE);
           cmd_ [totalLength]=(byte)DATAMAXSIZE;

          CommandAPDU cmd1 = new CommandAPDU( cmd_ );
          ResponseAPDU resp =	this.sendAPDU( cmd1, DISPLAY );

          byte[] result1 =resp.getBytes();
          if (typeINS==UNCIPHERFILE){
            leftpadding = (int)result1[result1.length-3];
          }
          System.arraycopy(result1, 0, result2, compteur, result1.length-2);
          compteur+=DATAMAXSIZE;

  			}
        inputstream.close();

        if (typeINS==UNCIPHERFILE) {
          int uncipherlength = result2.length - leftpadding;
          byte[] result4 = new byte [uncipherlength];
          System.arraycopy(result2, 0, result4, 0, uncipherlength);
          for(int i=0; i<result4.length;i++)
            System.out.println("result4 "+HexString.hexify( result4[i] ));
          writeOutputFile(result4, typeINS);
        }

        if (typeINS==CIPHERFILE) {
          writeOutputFile(result2, typeINS);
        }

      }catch(FileNotFoundException e){
        System.out.println(e.getMessage());
      }catch(IOException e){
        System.out.println(e.getMessage());
      }

    }
    void writeOutputFile(byte [] result2, byte typeINS){
      try{
        FileOutputStream fop = null;
        File file1;
        if (typeINS==CIPHERFILE) {
            file1 = new File("ciphered.txt");
        }else{
            file1 = new File("unciphered.txt");
        }
        fop = new FileOutputStream(file1);

        if (!file1.exists()) {
          file1.createNewFile();
        }
        fop.write(result2);
        fop.flush();
        fop.close();
      }catch(FileNotFoundException e){
        System.out.println(e.getMessage());
      }catch(IOException e){
        System.out.println(e.getMessage());
      }
    }

    void exit() {
  		loop = false;
  	}

  	void runAction( int choice ) {
  		switch( choice ) {
  			case 3: changeDesKey(); break;
  			case 2: cipherFile(UNCIPHERFILE); break;
  			case 1: cipherFile(CIPHERFILE); break;
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
