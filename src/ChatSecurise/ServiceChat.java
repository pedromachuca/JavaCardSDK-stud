import java.net.*;
import java.io.*;
import java.util.*;

public class ServiceChat extends Thread{

  final static int NBMAXUSER = 3;
  static int nbUsers = 0;
  static List<PrintStream> outputs = new ArrayList<>(NBMAXUSER);
  BufferedReader input;
  PrintStream output;
  Socket socket;
  static List<String> listUser= new ArrayList<>(NBMAXUSER);
  static List<String> listPassword= new ArrayList<>(NBMAXUSER);
  HashMap<String, PrintStream> database = new HashMap<String, PrintStream>();
  static List<String> connectedUser= new ArrayList<>(NBMAXUSER);

  String username;
  String password;

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
        output.println("Veuillez entrer votre mot de passe: ");
        password= askInput();
        while(!(listPassword.get(resSearch).equals(password))) {
          output.println("Mauvais mot de passe reessayer: ");
          password=askInput();
          auth=true;
        }
      }
      else{
        listUser.add(username);
        output.println("It is your first inscription please enter a password :");
        password= askInput();
        listPassword.add(password);
        auth=true;
      }
    return auth;
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
    for (String name:listUser) {
    output.println( " User "+id+" : "+name);
      id+=1;
    }
  }
  public void quit(){
    connectedUser.remove(username);
    try{
      socket.close();
    }catch( IOException e ) {
      System.out.println( "Probleme en fermant socket" );
    }
  }
  public void sendMsg(String[] message){
    PrintStream usertosend;
    usertosend = database.get(message[1]);
    usertosend.print(username+" : ");

    for (int i=2;i<message.length;i++) {
        usertosend.print(" "+message[i]);
    }
      usertosend.print("\n");
  }

  public void sendFile(String user, String fileName){
    try{
      File file = new File(fileName);
      BufferedReader br;
      String st;

         br = new BufferedReader(new FileReader(file));
        while ((st = br.readLine()) != null){
          System.out.println(st);
        }
    }catch(IOException e){
      System.out.println(e);
    }
  }

  public void help(){
    output.println("Liste des commandes disponibles :\n/list : donne la liste de utilisateurs\n/quit : permet de quitter le chat\n/sendMsg <user> <msg> : pour envoyer un message prive");
    output.println("/sendFile <user> <fileName> : pour envoyer un fichier en prive\n/help : pour afficher la liste des commandes\n/? : pour afficher la liste des commandes");
  }
  public void updatedb(){
    for (int i = 0 ; i < listUser.size() ; i++) {
      database.put(listUser.get(i), outputs.get(i));
    }
    System.out.println(database);
  }
  public void parseMsg(String message){
    String[] messageSplit = new String[100];
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
          sendFile(messageSplit[1], messageSplit[2]);
          break;
        case "/help":
          help();
          break;
        case "/?":
          help();
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
      output.println("Vous pouvez maintenant chatter :");
      while(true){
        message = input.readLine();
        parseMsg(message);
      }
    }catch( IOException e ){
      System.out.println( "probleme en fermant socket" );
    }
  }

  public synchronized void broadcast(String message){
      for (PrintStream outThread:outputs) {
        outThread.println( username+" :"+message);
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
