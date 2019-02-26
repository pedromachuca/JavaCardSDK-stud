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
// import org.bouncycastle.jce.provider.BouncyCastleProvider;

class ServerChat {

    public static void main(String argv[]) throws Exception{

        try {

          ServerSocket serversocket = new ServerSocket(1234);

          while (true){
              System.out.println( "Listenning 1234 ..." );
              new ServiceChat(serversocket.accept());
              System.out.println( "New client connected !" );
          }
        } catch( IOException e ) {
          System.out.println( "probleme de connexion" );
        }
    }
}


/*Faire l'authentification, on va remplacer la comparaison de 2 objets string avec de la cryptographie,
login associé a clé publique premiere connexion => clé publique (récupérer dans la carte a puce, l'envoi au server qui la stoke)
Crypto dechiffrement avec la cle privee dans la javacard
Pour la partie chiffrement des donnes on utilisera l'algo des deja utilisé par le passé (multiple de la cle DES)
Pour la cle RSA envoyé des données avec la mm taille que la cle.

*/
