package client;

import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.Cipher;
import java.lang.Math;
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
          System.out.println("before cipher");
          message = consoleVersResInput.readLine();
          System.out.println("before readliner");
          message= cipher(INS_DES_ECB_NOPAD_ENC, message);
          System.out.println("");

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
    public String decodeb64(String message){
      BASE64Decoder decoder;
      byte [] messageByte = new byte[message.length()];
      String b64toClient="";
      try{
        decoder = new BASE64Decoder();
        messageByte = decoder.decodeBuffer(message);
        b64toClient = new String(messageByte);
      }catch(Exception e){e.printStackTrace();}

      return b64toClient;
    }


    public String sendtoCard(byte typeINS, String message){

      BASE64Decoder decoder;
      BASE64Encoder encoder;
      String b64toServer="";
      int totalLength = 0;
      int leftpadding =0;
      int lengthRes = 0;

      try{
        byte [] messageByte = new byte[message.length()];

          if (typeINS ==INS_DES_ECB_NOPAD_DEC ) {
            decoder = new BASE64Decoder();
            messageByte = decoder.decodeBuffer(message);
            totalLength= messageByte.length;
             System.out.println("DMS "+DATAMAXSIZE);
             System.out.println("totalLength :"+totalLength);
          }
          else{
            messageByte = message.getBytes();
            totalLength= messageByte.length;
          }
          System.out.println("totalLength :"+totalLength);
          if (totalLength >=248) {
            DATAMAXSIZE = 248;
            leftpadding = (int)totalLength%DATAMAXSIZE;
            lengthRes =(int)Math.ceil((float)totalLength/8)*8;
          }
          else if (totalLength<248) {
            float div = (float)totalLength/8;
            DATAMAXSIZE = (int)Math.ceil(div)*8;
            leftpadding = (int)DATAMAXSIZE - totalLength;
            lengthRes = DATAMAXSIZE;
          }
          if (totalLength<248&&totalLength%8==0&&typeINS==INS_DES_ECB_NOPAD_ENC) {
            DATAMAXSIZE = DATAMAXSIZE +8;
            leftpadding=8;
            lengthRes = lengthRes+8;
            System.out.println("leftpadding : "+leftpadding);
            System.out.println("inside DMS "+DATAMAXSIZE);
          }
          if (totalLength>248&&totalLength%8==0) {
            lengthRes = lengthRes+8;
          }

         byte[] result = new byte[(int)DATAMAXSIZE];
         int compteur = 0;
         int data = 0;

         byte[] result2 = new byte [lengthRes];
         System.out.println("DMS "+DATAMAXSIZE);
         System.out.println("totalLength :"+totalLength);

         InputStream inputstream = new ByteArrayInputStream(messageByte);

         while(((data = inputstream.read(result)) >= 0) ){

           if (typeINS==INS_DES_ECB_NOPAD_ENC&&data!=DATAMAXSIZE){
             if (DATAMAXSIZE >=248 && compteur !=0) {
               float div = (float)leftpadding/8;
               DATAMAXSIZE = (int)Math.ceil(div)*8;
               leftpadding = (int)DATAMAXSIZE - leftpadding;
               if (leftpadding==0) {
                 leftpadding = 8;
                 DATAMAXSIZE = DATAMAXSIZE +8;
               }
             }
             for (int i=DATAMAXSIZE-leftpadding;i<DATAMAXSIZE;i++ ) {
                 result[i]=(byte)leftpadding;
               }
           }

           byte[] cmd_part = {CLA, typeINS, P1, P2, (byte)DATAMAXSIZE};

           int size_part = cmd_part.length;

           int lengthCmd =DATAMAXSIZE+size_part;
           byte[] cmd_= new byte[lengthCmd+1];

           System.arraycopy(cmd_part, 0, cmd_, 0, size_part);
           System.arraycopy(result, 0, cmd_, size_part, DATAMAXSIZE);

           cmd_ [lengthCmd]=(byte)DATAMAXSIZE;

          CommandAPDU cmd1 = new CommandAPDU( cmd_ );
          ResponseAPDU resp =	this.sendAPDU( cmd1, DISPLAY );

          byte[] result1 =resp.getBytes();

          if (typeINS==INS_DES_ECB_NOPAD_DEC){
            leftpadding = (int)(result1[result1.length-3]&0xff);
          }
          System.arraycopy(result1, 0, result2, compteur, DATAMAXSIZE);
          compteur+=DATAMAXSIZE;
          if (typeINS==INS_DES_ECB_NOPAD_DEC&&(totalLength-compteur)<248) {
            DATAMAXSIZE = (totalLength-compteur);
          }
        }

        if (typeINS==INS_DES_ECB_NOPAD_DEC) {
          if (leftpadding>0){

            System.out.println("leftpadding :"+leftpadding);
            int uncipherlength =totalLength- leftpadding;
            System.out.println("uncipherlength :"+uncipherlength);
            byte[] result4 = new byte [uncipherlength];
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
        String[] messageSplit = new String[300];
        String[] messageSplit1 = new String[300];

        messageSplit = message.split(" ");
        if (messageSplit.length>=2) {
          messageSplit1[0] =messageSplit[0];
          messageSplit1[1] =messageSplit[1];
          messageSplit1[2] ="";
        }

        for (int i=2;i<messageSplit.length ;i++ ) {
          messageSplit1[2] +=messageSplit[i]+" ";
        }
        for (int i=0;i<6 ;i++ ) {
          System.out.println("Cipher :"+messageSplit1[i] );
        }

        switch(toDo){
          //tosend Broadcast
          case 1:
            toSend =sendtoCard(typeINS,message);
            toSend = "/broadcast "+toSend;
            break;
          //receive broadcast
          case 2:
            toSend =sendtoCard(typeINS,messageSplit[2]);
            toSend = messageSplit[1]+toSend;
            break;
          //to send /sendMsg
          case 3:
            toSend =sendtoCard(typeINS,messageSplit1[2]);
            toSend = messageSplit[0]+" "+messageSplit[1]+" "+toSend;
            System.out.println("toSend :"+toSend );
            break;
          //receive /sendMsg
          case 4:
            System.out.println("messageSplit[1] :"+messageSplit[1] );
            toSend =sendtoCard(typeINS,messageSplit[1]);
            toSend = messageSplit[0]+" "+toSend;
            System.out.println("toSend :"+toSend );
            break;
          //receive /quit
          case 5:
            toSend ="/quit";
            break;
          case 6:
            toSend ="/help";
            break;
          case 7:
            toSend ="/list";
            break;
          //send /sendFile
          case 8:
            String tmp =getFile(messageSplit1[2]);
            toSend =sendtoCard(typeINS,tmp);
            toSend = messageSplit[0]+" "+messageSplit[1]+" "+messageSplit1[2]+toSend;
            System.out.println("toSend :"+toSend );
            break;
          //receive file
          case 9:
            System.out.println("messageSplit[1] :"+messageSplit[1] );
            toSend =sendtoCard(typeINS,messageSplit[3]);
            writeFile(toSend, messageSplit[2]);
            toSend = messageSplit[1]+" sent you the file : "+messageSplit[2];
            System.out.println(messageSplit[1]+"toSend :"+toSend );
            break;
        //case default
          case 0:
            message = decodeb64(messageSplit[1]);
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

      for (int i=0;i<messageSplit.length ;i++ ) {
        System.out.println("checkMsg :"+messageSplit[i] );
      }

      if(message.startsWith("/")){
        if (messageSplit[0].equals("/broadcast")) {
          return 2;
        }
        else if (messageSplit[0].equals("/sendMsg")) {
          return 3;
        }
        else if (messageSplit[0].equals("/quit")) {
          return 5;
        }
        else if (messageSplit[0].equals("/help")||messageSplit[0].equals("/?")) {
          return 6;
        }
        else if (messageSplit[0].equals("/list")) {
          return 7;
        }
        else if (messageSplit[0].equals("/sendFile")) {
          return 8;
        }
      }
      else if ( message.startsWith("@")) {
        if ( message.startsWith("@help")) {
          return 0;
        }
        else if ( message.startsWith("@list")) {
          return 0;
        }
        else if ( message.startsWith("@sendFile")) {
          return 9;
        }
        else {
          return 4;
        }
      }
      else{
        return 1;
      }
      return 0;
    }

    public String getFile(String filename){

      File file= null;
      String filedata="";
      file = new File(filename);
      long fileLength = file.length();
      byte [] result = new byte [(int)fileLength];
      int data =0;
      try{


        FileInputStream inputstream = new FileInputStream(file);

        while(((data = inputstream.read(result)) >= 0) ){

        }
        // BufferedReader reader = new BufferedReader(new FileReader(filename));
        // StringBuilder stringBuilder = new StringBuilder();
        // String line = null;
        // String ls = System.getProperty("line.separator");
        // while ((line = reader.readLine()) != null) {
        // 	stringBuilder.append(line);
        	// stringBuilder.append(ls);
        // }
        // delete the last new line separator
        // stringBuilder.deleteCharAt(stringBuilder.length() - 1);
        // reader.close();
        //
        // filedata = stringBuilder.toString();
        BASE64Encoder encoder = new BASE64Encoder();
        filedata = encoder.encode(result).replaceAll(System.getProperty("line.separator"),"");

      }catch(IOException e){
        System.out.println(e);
      }
      System.out.println(filedata);
      return filedata;
    }

    public void writeFile(String filedata, String filename){
      OutputStream os = null;
      System.out.println("\nFILEDATA :"+ filedata);
      int cursor;
        try {
            // os = new FileOutputStream(new File(filename));
            os = new FileOutputStream(new File("AfterVictory.gif"));
            BASE64Decoder decoder = new BASE64Decoder();
            byte [] messageByte = decoder.decodeBuffer(filedata);
            os.write(messageByte, 0, messageByte.length);

        } catch (IOException e) {
            e.printStackTrace();
        }finally{
            try {
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
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
        System.out.println("test");

        message = resVersConsoleInput.readLine();
        System.out.println("DECIPHer : "+message);
        message = cipher(INS_DES_ECB_NOPAD_DEC, message);
        System.out.println("After DECIPHer : "+message);

        resVersConsoleOutput.println(message);
      }
    }catch( IOException e ) {
      java.lang.System.exit(0) ;
      System.out.println("test :"+e);
    }
  }

}
