import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

import java.net.*;
import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServiceChat extends Thread{

  final static int NBMAXUSER = 3;
  static int nbUsers = 0;
  static List<PrintStream> outputs = new ArrayList<>(NBMAXUSER);
  BufferedReader input;
  PrintStream output;
  Socket socket;
  static List<String> listUser= new ArrayList<>(NBMAXUSER);
  static List<String> connectedUser= new ArrayList<>(NBMAXUSER);

  static HashMap<String, PrintStream> database = new HashMap<String, PrintStream>();
  static HashMap<String, PublicKey> publicRSAKey = new HashMap<String, PublicKey>();

  String username;
  String pubkey;
  boolean loop = true;
  byte[] challengeBytes = new byte[128];

  public ServiceChat( Socket socket ) {
      this.socket = socket;
      this.start();
  }

  public int search(List<String> list, String toSearch){
    boolean found =false;
    int i =0;
    int result = -1;
    while(i<list.size()&&!found)
      if (toSearch.equals(list.get(i++))){
        found = true;
        result=i;
      }
    return result;
  }

  public String askInput(){
    String askedInput="";
    try {
       askedInput= input.readLine();
    } catch( IOException a ) {
      System.out.println( "Probleme d'IO" );
    }
    return askedInput;
  }

  public boolean authentification(){

      boolean auth =true;
      int resSearch=0;
      output.println("Veuillez entrer un nom d'utilisateur : ");
      username = askInput();

      while(search(connectedUser, username)>=0){
        output.println("Le nom d'utilisateur existe deja reessayer : ");
        username = askInput();
      }

      connectedUser.add(username);
      resSearch=search(listUser, username);

      if (resSearch>=0) {
        output.println("/chall");
        challenge();
        auth = true;
      }
      else{
        output.println("/ok");
        String encodedPublicKey = "";
        encodedPublicKey = askInput();
        decodePub(encodedPublicKey);
        listUser.add(username);
        auth=true;
      }
    return auth;
  }
  public void challenge(){
    // How to crypt and uncrypt using RSA_NOPAD: 4 Steps

		// Get Cipher able to apply RSA_NOPAD (step 1)
		// (must use "Bouncy Castle" crypto provider)
    try{
      Security.addProvider(new BouncyCastleProvider());
      Cipher cRSA_NO_PAD = Cipher.getInstance( "RSA/NONE/NoPadding", "BC" );

      // Get challenge data (step 2)
      final int DATASIZE = 128;				//128 to use with RSA1024_NO_PAD
      Random r = new Random( (new Date()).getTime() );
      r.nextBytes( challengeBytes );
      challengeBytes[0] &=127;
      // Crypt with public key (step 3)
      cRSA_NO_PAD.init( Cipher.ENCRYPT_MODE, publicRSAKey.get(username));
      byte[] ciphered = new byte[DATASIZE];
      System.out.println( "*" );
      cRSA_NO_PAD.doFinal(challengeBytes, 0, DATASIZE, ciphered, 0);
      System.out.println( "*" );


      String encodedString = Base64.getEncoder().encodeToString(ciphered);
      output.println(encodedString);
      encodedString = input.readLine();
      byte[] decodedBytes = Base64.getDecoder().decode(encodedString);

      System.out.println("Challenge OK !");
      int compteur=0;
      for (int i=0;i<decodedBytes.length ;i++ ) {
          if (decodedBytes[i]==challengeBytes[i]) {
              compteur+=1;
          }
      }
      if (compteur==128) {
          output.println("/Challok");
      }


    }catch(Exception e){
      System.out.println("Problem with Challenge :"+e.getMessage());
    }


  }

  public void decodePub(String encodedPublicKey){

    byte[] decodedBytes = Base64.getDecoder().decode(encodedPublicKey);
    try{

      PublicKey publicKey1 = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedBytes));
      publicRSAKey.put(username, publicKey1);
    }catch(Exception e){
      System.out.println(e.getMessage());
    }

  }

  public boolean initThread(){

    boolean initok = false;

    if (nbUsers <= NBMAXUSER) {
      try {
        input = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
        output = new PrintStream( socket.getOutputStream() );
        outputs.add(output);
      } catch( IOException e ) {
        try {
          socket.close();
        } catch( IOException e2 ) {
          System.out.println( "probleme en fermant socket" );
        }
      }
      initok=true;
    }
    else{
      System.out.println("Probleme avec la methode initThread");
    }
    return initok;
  }


  public void list(){
    int id = 0;
    String listUser="";
    for (String name:connectedUser) {
      listUser+="\nUser" +id+" : "+name+"\n";
      id+=1;
    }
    String encodedString = Base64.getEncoder().encodeToString(listUser.getBytes());
    output.println( "@list "+encodedString);

  }


  public void quit(){
    connectedUser.remove(username);
    database.remove(username);
    outputs.remove(output);
    try{
      output.close();
      input.close();
      socket.close();
      loop = false;
    }catch( IOException e ) {
      System.out.println( "Probleme en fermant socket : "+e);
    }
  }
  public void sendMsg(String[] message){
    PrintStream usertosend;
    try{
      usertosend = database.get(message[1]);
      usertosend.println("@"+username+": "+message[2]);
    }catch(Exception e){
      e.printStackTrace();
    }

  }

  public void sendFile(String user, String filename, String filedata){
    PrintStream usertosend;

    try{
      usertosend = database.get(user);
      usertosend.println("@sendFile "+username+" "+filename+" "+filedata);
    }catch(Exception e){
      e.printStackTrace();
    }
  }

  public void help(){
    byte [] listHelp = "\nListe des commandes disponibles :\n/list : donne la liste de utilisateurs\n/quit : permet de quitter le chat\n/sendMsg <user> <msg> : pour envoyer un message prive \n/sendFile <user> <fileName> : pour envoyer un fichier en prive\n/help : pour afficher la liste des commandes\n/? : pour afficher la liste des commandes".getBytes();
    String encodedString = Base64.getEncoder().encodeToString(listHelp);
    output.println("@help "+encodedString );
  }


  public synchronized void updatedb(){
    database.put(username, output);
  }

  public void parseMsg(String message){
    String[] messageSplit = new String[300];
    messageSplit = message.split(" ");

    if(message.startsWith("/")){
      switch(messageSplit[0]){
        case "/list":
          list();
          break;
        case "/quit":
          quit();
          break;
        case "/sendMsg":
          sendMsg(messageSplit);
          break;
        case "/sendFile":
        //encoder les fichiers en base64
          sendFile(messageSplit[1], messageSplit[2], messageSplit[3]);
          break;
        case "/help":
          help();
          break;
        case "/?":
          help();
          break;
        case "/broadcast":
          broadcast(messageSplit[1]);
          break;
        default:
          break;
      }
    }
    else{
      broadcast(message);
    }
  }


  public void mainLoop(){
    updatedb();
    String message;
    int cmd=0;
    try{
      output.println("/Vous pouvez maintenant chatter :");
      while(loop){
        message = input.readLine();
        parseMsg(message);
      }
    }catch( IOException e ){
      System.out.println("test1"+e);
    }
  }

  public synchronized void broadcast(String message){
      for (PrintStream outThread:outputs) {
        outThread.println("/broadcast "+username+": "+message);
      }
  }
  //outputs.foreach((n) ->  n.println( "Message :"+message));
	public void run() {

    if (initThread()) {
      if (authentification()) {
        mainLoop();
      }
      else{
        System.out.println("Probleme avec authentification");
      }
    }
    else{
      System.out.println("Probleme avec initThread");
    }
	}

}
