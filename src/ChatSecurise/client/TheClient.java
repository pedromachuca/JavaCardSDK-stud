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
import sun.misc.BASE64Decoder;

public class TheClient extends Thread{

  BufferedReader resVersConsoleInput;
  BufferedReader consoleVersResInput;
  PrintStream resVersConsoleOutput;
  PrintStream consoleVersResOutput;
  Socket socket;
  boolean loop = true;

  byte [] modulus = new byte[128];
  byte [] exponent = new byte[3];

  private final static byte CLA                    = (byte)0x90;
  private final static byte INS_GET_PUBLIC_RSA_KEY = (byte)0xFE;
  private final static byte INS_RSA_DECRYPT        = (byte)0xA2;
  private final static byte P1				             = (byte)0x00;
	private final static byte P2					           = (byte)0x00;
  private final static byte INS_DES_ECB_NOPAD_ENC  = (byte)0x20;
  private final static byte INS_DES_ECB_NOPAD_DEC  = (byte)0x21;



  private PassThruCardService servClient = null;
  final static boolean DISPLAY = true;
  private  int DATAMAXSIZE             = 248;

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
          message= cipher(INS_DES_ECB_NOPAD_ENC, message);
          consoleVersResOutput.println(message);
          if (message.equals("/quit")) {
              consoleVersResInput.close();
              consoleVersResOutput.close();
              loop =false;
              java.lang.System.exit(0) ;
          }
        }
      SmartCard.shutdown();
      }catch( IOException e ) {
        java.lang.System.exit(0) ;

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

    }

    public String sendtoCard(byte typeINS, String message){

        BASE64Decoder decoder;
        BASE64Encoder encoder;
        String b64toServer="";
        int lengthM = 0;
        byte [] messageByte = new byte[DATAMAXSIZE];

        try{
          if (typeINS ==INS_DES_ECB_NOPAD_DEC ) {
            decoder = new BASE64Decoder();

              messageByte = decoder.decodeBuffer(message);

             lengthM= messageByte.length;
             System.out.println(DATAMAXSIZE);
             System.out.println(lengthM);
          }
          else{
            messageByte = message.getBytes();
            lengthM= messageByte.length;
          }

          int totalLength = 0;

          if (lengthM <248 && lengthM>8 && lengthM%8!=0 ) {
             int rest = lengthM%8;
             int toAdd = 8-rest;
             DATAMAXSIZE = toAdd+lengthM;
          }
          if (lengthM<8) {
            DATAMAXSIZE = 8;
          }
          if (lengthM%8==0) {
            DATAMAXSIZE = lengthM;
          }

           int leftpadding = (int)DATAMAXSIZE -((int)lengthM%DATAMAXSIZE);
           System.out.println("DMS : "+DATAMAXSIZE);
           System.out.println("LP : "+leftpadding);
           System.out.println("lengthM : "+lengthM);
           if (typeINS==INS_DES_ECB_NOPAD_DEC){
             totalLength = (int)lengthM;
           }
           else{
               totalLength =(int)lengthM+(int)leftpadding;
           }
           boolean check = false;
           if (leftpadding%8==0&&typeINS==INS_DES_ECB_NOPAD_ENC) {
             DATAMAXSIZE = DATAMAXSIZE+8;
             totalLength =DATAMAXSIZE;
             check = true;
           }
           System.out.println("DMS : "+DATAMAXSIZE);
           System.out.println("LP : "+leftpadding);
           System.out.println("totalLength : "+totalLength);

           byte[] result = new byte[(int)DATAMAXSIZE];
           int compteur = 0;
           int data = 0;
           String ciphered = "";

           byte[] result2 = new byte [totalLength];
           InputStream inputstream = new ByteArrayInputStream(messageByte);

           while(((data = inputstream.read(result)) >= 0) ){

             byte[] cmd_part = {CLA, typeINS, P1, P2, (byte)DATAMAXSIZE};

             int size_part = cmd_part.length;

             totalLength =DATAMAXSIZE+size_part;
             byte[] cmd_= new byte[totalLength+1];

             System.arraycopy(cmd_part, 0, cmd_, 0, size_part);

             if (typeINS==INS_DES_ECB_NOPAD_ENC&&data!=DATAMAXSIZE&&check==false){
               for (int i=DATAMAXSIZE-leftpadding;i<DATAMAXSIZE;i++ ) {
                   result[i]=(byte)leftpadding;
                 }
             }
             if (typeINS==INS_DES_ECB_NOPAD_ENC&&data!=DATAMAXSIZE&&check==true){
               for (int i=DATAMAXSIZE-8;i<DATAMAXSIZE;i++ ) {
                   System.out.println("leftpadding "+leftpadding);
                   result[i]=(byte)0x08;
                 }
             }

             System.arraycopy(result, 0, cmd_, size_part, DATAMAXSIZE);
             cmd_ [totalLength]=(byte)DATAMAXSIZE;

            CommandAPDU cmd1 = new CommandAPDU( cmd_ );
            ResponseAPDU resp =	this.sendAPDU( cmd1, DISPLAY );

            byte[] result1 =resp.getBytes();

            if (typeINS==INS_DES_ECB_NOPAD_DEC){
              leftpadding = (int)(result1[result1.length-3]&0xff);
            }
            System.arraycopy(result1, 0, result2, compteur, DATAMAXSIZE);
            compteur+=DATAMAXSIZE;
          }

          if (typeINS==INS_DES_ECB_NOPAD_DEC) {
            if (leftpadding>0){

              System.out.println("uncipherlength :"+leftpadding);
              int uncipherlength =result2.length- leftpadding;;
              byte[] result4 = new byte [300];
              System.arraycopy(result2, 0, result4, 0, uncipherlength);
              if (typeINS ==INS_DES_ECB_NOPAD_DEC ) {
                b64toServer = new String(result4);
              }
            }
            else{
              System.out.println("Wrong key to decipher");
            }
          }


          if (typeINS ==INS_DES_ECB_NOPAD_ENC ) {
            for (int i=0;i<result2.length ;i++ ) {
              System.out.print(" "+result2[i]);
            }
            System.out.print("\nfin res 3\n");

             encoder = new BASE64Encoder();
             b64toServer = encoder.encode(result2).replaceAll(System.getProperty("line.separator"),"");
          }

        }catch(IOException e){
          System.out.println(e.getMessage());
        }

      return b64toServer;
    }


    String cipher(byte typeINS, String message){
        String toSend="";
        int toDo = checkMsg(message);

        switch(toDo){
          case 1:
            toSend =sendtoCard(typeINS,message);
            break;
          case 0:
            System.out.print(message);
            break;
          default:
            break;
        }

        return toSend;
    }

    public int checkMsg(String message){
      String[] messageSplit = new String[300];
      messageSplit = message.split(" ");

      if(message.startsWith("/")){
        // switch(messageSplit[0]){
          // case "/list":
          //   list();
          //   break;
          // case "/quit":
          //   quit();
          //   break;
          // case "/sendMsg":
          //   sendMsg(messageSplit);
          //   break;
          // case "/sendFile":
          // //encoder les fichiers en base64
          //   sendFile(messageSplit[1], messageSplit[2]);
          //   break;
          // case "/help":
          //   help();
          //   break;
          // case "/?":
          //   help();
          //   break;
        //   default:
        //     break;
        // }
      }
      else{
        return 1;
      }
      return 0;
    }

    public boolean sendPubKey(){

      byte[] cmd_ = {CLA, INS_GET_PUBLIC_RSA_KEY, P1, (byte)0x00, (byte)0x00};
      CommandAPDU cmd = new CommandAPDU( cmd_ );
      System.out.println("Modulus expected...Avec 0x00");
      ResponseAPDU resp = this.sendAPDU( cmd, DISPLAY );
      byte[] tmpmodulus = resp.getBytes();
      System.arraycopy(tmpmodulus, 1, modulus, 0, 128);


      byte[] cmd_1 = {CLA, INS_GET_PUBLIC_RSA_KEY, P1, (byte)0x01, (byte)0x00};
      CommandAPDU cmd1 = new CommandAPDU( cmd_1 );
      System.out.println("Exponent expected... Avec 0x01");
      ResponseAPDU resp1 = this.sendAPDU( cmd1, DISPLAY );
      byte[] tmpexponent = resp1.getBytes();

      System.arraycopy(tmpexponent, 1, exponent, 0, 3);

      String pubkey = generatePub();
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

      }catch(Exception e){
        System.out.println( "no such algo"+e );
      }
      return b64PublicKey;
    }

    public void sendChall(){

      String encodedString ="";
      BASE64Decoder decoder;
      BASE64Encoder encoder;
      byte [] decodedBI = new byte[128];

      try{
        encodedString = resVersConsoleInput.readLine();
        decoder = new BASE64Decoder();
        decodedBI = decoder.decodeBuffer(encodedString);

        for (int i=0;i<decodedBI.length ;i++ ) {
            System.out.print(" "+decodedBI[i]);
        }
        byte[] cmd_part = {CLA, INS_RSA_DECRYPT, P1, P2, (byte)0x80};
        int size_part = cmd_part.length;

        int totalLength =128+size_part;
        byte[] cmd_1= new byte[totalLength+1];

        System.arraycopy(cmd_part, 0, cmd_1, 0, size_part);
        System.arraycopy(decodedBI, 0, cmd_1, size_part, 128);
        cmd_1[totalLength]=(byte)0x80;

        CommandAPDU cmd2 = new CommandAPDU( cmd_1 );
        System.out.println("Decrypt RSA...");
        displayAPDU(cmd2);
        ResponseAPDU resp = this.sendAPDU( cmd2, DISPLAY );
        byte[] clairBI = resp.getBytes();

        byte[] ChallRep = new byte[128];
        System.arraycopy(clairBI, 0, ChallRep, 0, 128);

        encoder = new BASE64Encoder();
        String b64PublicKey = encoder.encode(ChallRep).replaceAll(System.getProperty("line.separator"),"");
        consoleVersResOutput.println(b64PublicKey);

      }catch(Exception e){
        System.out.println("Problem with sendChall :"+e.getMessage());
      }
   }


   public String cmd(){

     String message ="";
     try{
          message = resVersConsoleInput.readLine();
          System.out.println(message);
          message = consoleVersResInput.readLine();
          consoleVersResOutput.println(message);
          message = resVersConsoleInput.readLine();

          if(message.equals("/ok")){
            return "/ok";
          }
          if (message.equals("/chall")) {
            return "/chall";
          }

     }catch(IOException e){
       System.out.println("Inside cmd()");
     }
     return "";
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

    boolean loop1 = true;
    while(loop1){
      String cmd = cmd();
      if (cmd.equals("/ok")){
        sendPubKey();
        loop1=false;
      }
      if (cmd.equals("/chall")) {
        System.out.println("before sendchall ");
        sendChall();
        try{
          String message = resVersConsoleInput.readLine();
          if (message.equals("/Challok")) {

            loop1=false;
          }
        }catch(IOException e){
          System.out.println(e.getMessage());
        }
      }
    }
  }

  public void run(){
    try{
      while(loop){
        String message="";
        message = resVersConsoleInput.readLine();
        message = cipher(INS_DES_ECB_NOPAD_DEC, message);
        resVersConsoleOutput.println(message);
      }
    }catch( IOException e ) {
      java.lang.System.exit(0) ;
      System.out.println("test :"+e);
    }
  }

}
