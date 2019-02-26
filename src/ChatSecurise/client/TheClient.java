package client;

import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.Cipher;

import java.net.*;
import java.io.*;
import java.util.Date;
import java.util.Random;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Encoder;

public class TheClient extends Thread{

  BufferedReader resVersConsoleInput;
  BufferedReader consoleVersResInput;
  PrintStream resVersConsoleOutput;
  PrintStream consoleVersResOutput;
  Socket socket;
  boolean loop = true;

  byte [] modulus = new byte[255];
  byte [] exponent = new byte[4];

  private final static byte CLA                    = (byte)0x90;
  private final static byte INS_GET_PUBLIC_RSA_KEY = (byte)0xFE;
  private final static byte P1				             = (byte)0x00;
	private final static byte P2					           = (byte)0x00;


  private PassThruCardService servClient = null;
  final static boolean DISPLAY = true;

  public static void main(String argv[]) throws Exception{
    try{
      int port = 1234;
      String ip = "127.0.0.1";
      Socket socket;
      socket = new Socket(ip, port);

      new TheClient(socket);

    }catch( IOException e ) {
        System.out.println( "Probleme de connexion" );
    }
  }


  public TheClient(Socket socket){

    this.socket = socket;
    if (initStreams()) {
      try {
        SmartCard.start();
        System.out.print( "Smartcard inserted?... " );
        CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null);
        SmartCard sm = SmartCard.waitForCard (cr);
        if (sm != null) {
          System.out.println ("got a SmartCard object!\n");
        } else
          System.out.println( "did not get a SmartCard object!\n" );
        initNewCard( sm );
      } catch( Exception e ) {
        System.out.println( "TheClient error: " + e.getMessage() );
      }
      mainLoop();

      this.start();
      try{
        String message="";
        while(loop){
          message = consoleVersResInput.readLine();
          consoleVersResOutput.println(message);
        }
      SmartCard.shutdown();
      }catch( IOException e ) {
        System.out.println( "Probleme de lecture" );
      }
    }
    else{
      System.out.println( "Probleme d'initialisation des streams" );
      java.lang.System.exit(0) ;
    }
      java.lang.System.exit(0) ;
  }



  private ResponseAPDU sendAPDU(CommandAPDU cmd) {
		return sendAPDU(cmd, DISPLAY);
	}

	private ResponseAPDU sendAPDU( CommandAPDU cmd, boolean display ) {
		ResponseAPDU result = null;
		try {
			result = servClient.sendCommandAPDU( cmd );
			if(display)
				displayAPDU(cmd, result);
		} catch( Exception e ) {
			System.out.println( "Exception caught in sendAPDU: " + e.getMessage() );
			java.lang.System.exit( -1 );
		}
		return result;
	}

  	/************************************************
  	 * *********** BEGINNING TOOLS ***************
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
  	 * *********** ENDING TOOLS ***************
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

    	// authentification();
    }

   public boolean authentification(){

     byte[] cmd_ = {CLA, INS_GET_PUBLIC_RSA_KEY, P1, (byte)0x00, (byte)0x00};
     CommandAPDU cmd = new CommandAPDU( cmd_ );
     System.out.println("Modulus expected...Avec 0x00");
     ResponseAPDU resp = this.sendAPDU( cmd, DISPLAY );
     modulus = resp.getBytes();

     byte[] cmd_1 = {CLA, INS_GET_PUBLIC_RSA_KEY, P1, (byte)0x01, (byte)0x00};
     CommandAPDU cmd1 = new CommandAPDU( cmd_1 );
     System.out.println("Exponent expected... Avec 0x01");
     ResponseAPDU resp1 = this.sendAPDU( cmd1, DISPLAY );
     exponent = resp.getBytes();
     String pubkey = generatePub();
     // try{
     //   sleep(10);
     // }catch(Exception InterruptedException){
     //   System.out.println("Sleep exepction");
     // }
      consoleVersResOutput.println(pubkey);

     return true;
   }

   public String generatePub(){
     String b64PublicKey = "";

     String mod =  HexString.hexify( modulus );
     mod = mod.replaceAll( " ", "" );
     mod = mod.replaceAll( "\n", "" );

     String exp =  HexString.hexify( exponent );
     exp = exp.replaceAll( " ", "" );
     exp = exp.replaceAll( "\n", "" );

     // Load the keys from String into BigIntegers (step 3)
     BigInteger BImodulus = new BigInteger(mod, 16);
     BigInteger BIexponent = new BigInteger(exp, 16);

     try{

       RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(BImodulus, BIexponent);
       KeyFactory factory = KeyFactory.getInstance( "RSA" );
       PublicKey pub = factory.generatePublic(publicSpec);
       byte[] encodedPublicKey = pub.getEncoded();
       BASE64Encoder encoder = new BASE64Encoder();
       b64PublicKey = encoder.encode(encodedPublicKey).replaceAll(System.getProperty("line.separator"),"");
       System.out.println("Public key : "+b64PublicKey);

     }catch(Exception NoSuchAlgorithmException){
       System.out.println( "no such algo" );
     }
     return b64PublicKey;
   }

   public void nameOk(){

     // String message ="";
     // try{
     //   message = resVersConsoleInput.readLine();
     //   while(!message.equals("OK")){
     //     message = resVersConsoleInput.readLine();
     //   }
     // }catch(Exception IOException){
     //   System.out.println("nameok");
     // }
     try{
       consoleVersResInput.readLine();
     }catch( IOException e ){
       System.out.println( "Probleme d'initialisation des streams" );
     }
   }

  public boolean initStreams(){
    boolean result= false;
    try{
      resVersConsoleInput = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
      resVersConsoleOutput = new PrintStream(System.out);

      consoleVersResInput =  new BufferedReader( new InputStreamReader(System.in));
      consoleVersResOutput = new PrintStream( socket.getOutputStream() );
      result = true;
    }catch( IOException e ){
      System.out.println( "Probleme d'initialisation des streams" );
    }
    return result;
  }

  public void mainLoop(){
    nameOk();
    authentification();
  }

  public void run(){
    try{
      while(loop){
        String message="";
        message = resVersConsoleInput.readLine();
        resVersConsoleOutput.println(message);
      }
    }catch( IOException e ) {
        System.out.println( "Probleme de lecture" );
    }
  }

}