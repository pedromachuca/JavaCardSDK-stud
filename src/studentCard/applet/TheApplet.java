package applet;


import javacard.framework.*;

public class TheApplet extends Applet {

	/*
		enter write pin => pour pouvoir ecrire le noms 1111
		enter read pin pour pouvoir lire le nom 0000
	*/

	static final byte UPDATECARDKEY				= (byte)0x14;
	static final byte UNCIPHERFILEBYCARD			= (byte)0x13;
	static final byte CIPHERFILEBYCARD			= (byte)0x12;
	static final byte CIPHERANDUNCIPHERNAMEBYCARD		= (byte)0x11;
	static final byte READFILEFROMCARD			= (byte)0x10;
	static final byte WRITEFILETOCARD			= (byte)0x09;
	static final byte UPDATEWRITEPIN			= (byte)0x08;
	static final byte UPDATEREADPIN				= (byte)0x07;
	static final byte DISPLAYPINSECURITY			= (byte)0x06;
	static final byte DESACTIVATEACTIVATEPINSECURITY	= (byte)0x05;
	static final byte ENTERREADPIN				= (byte)0x04;
	static final byte ENTERWRITEPIN				= (byte)0x03;
	static final byte READNAMEFROMCARD			= (byte)0x02;
	static final byte WRITENAMETOCARD			= (byte)0x01;
	static final byte DATAMAXSIZE =(short)0x02;

  //Write and read name
	final static short nameSize = (short)32;
	static byte[] name = new byte[nameSize];

	// Pin to enter to unlock write and read function to the card
	OwnerPIN pinwrite;
	OwnerPIN pinread;
	final byte PIN_VERIFY =(byte)0x20;
	final short SW_VERIFICATION_FAILED = (short)0x6300;
	final short SW_PIN_VERIFICATION_REQUIRED = (short)0x6301;
	//If secutity is set or not
	boolean security = true;
	static byte [] tableFile = new byte[2024];



	protected TheApplet() {

		byte[] WritePinCode = {(byte)0x31,(byte)0x31,(byte)0x31,(byte)0x31}; // PIN code "1111"
		byte[] ReadPinCode = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30}; // PIN code "0000"
		pinwrite = new OwnerPIN((byte)3,(byte)8);  				// 3 tries 8=Max Size
		pinread = new OwnerPIN((byte)3,(byte)8);  				// 3 tries 8=Max Size

		pinwrite.update(WritePinCode,(short)0,(byte)4); 				// from pincode, offset 0, length
		pinread.update(ReadPinCode,(short)0,(byte)4); 				// from pincode, offset 0, length 4
		this.register();
	}


	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new TheApplet();
	}


	public boolean select() {
		return true;
	}


	public void deselect() {
	}


	public void process(APDU apdu) throws ISOException {
		if( selectingApplet() == true )
			return;

		byte[] buffer = apdu.getBuffer();

		switch( buffer[1] ) 	{
			case UPDATECARDKEY: updateCardKey( apdu ); break;
			case UNCIPHERFILEBYCARD: uncipherFileByCard( apdu ); break;
			case CIPHERFILEBYCARD: cipherFileByCard( apdu ); break;
			case CIPHERANDUNCIPHERNAMEBYCARD: cipherAndUncipherNameByCard( apdu ); break;
			case READFILEFROMCARD: readFileFromCard( apdu ); break;
			case WRITEFILETOCARD: writeFileToCard( apdu ); break;
			case UPDATEWRITEPIN: updateWritePIN( apdu ); break;
			case UPDATEREADPIN: updateReadPIN( apdu ); break;
			case DISPLAYPINSECURITY: displayPINSecurity( apdu ); break;
			case DESACTIVATEACTIVATEPINSECURITY: desactivateActivatePINSecurity( apdu ); break;
			case ENTERREADPIN: enterReadPIN( apdu ); break;
			case ENTERWRITEPIN: enterWritePIN( apdu ); break;
			case READNAMEFROMCARD: readNameFromCard( apdu ); break;
			case WRITENAMETOCARD: writeNameToCard( apdu ); break;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}


	void updateCardKey( APDU apdu ) {
	}


	void uncipherFileByCard( APDU apdu ) {
	}


	void cipherFileByCard( APDU apdu ) {
	}


	void cipherAndUncipherNameByCard( APDU apdu ) {
	}


	void readFileFromCard( APDU apdu ) {
		byte[] buffer = apdu.getBuffer();
		if(buffer[2]==0){
			Util.arrayCopy(tableFile,(byte)1,buffer,(short)0,tableFile[0]);
			apdu.setOutgoingAndSend((short)0,tableFile[0]);
		}
		if(buffer[2]==1){
			Util.arrayCopy(tableFile,(byte)(tableFile[0]+3),buffer,(short)0,(byte)((tableFile[(tableFile[0]+1)])*DATAMAXSIZE));
			apdu.setOutgoingAndSend((short)0,(short)((tableFile[tableFile[0]+1])*DATAMAXSIZE));
		}
		if(buffer[2]==2&&tableFile[(tableFile[0]+2)]!=0){
			Util.arrayCopy(tableFile,(byte)(tableFile[0]+3+(tableFile[(tableFile[0]+1)])*DATAMAXSIZE),buffer,(short)0,(byte)(tableFile[(tableFile[0]+2)]));
			apdu.setOutgoingAndSend((short)0,(short)(tableFile[(tableFile[0]+2)]));
		}
		// Util.arrayCopy(tableFile,(byte)0,buffer,(short)0,(byte)100);
		// apdu.setOutgoingAndSend((short)0,(short)100);
	}

	/*
	Envoyer :
	nom du fichier : file => 4 octets

	A stocker dans un tableau dans l'applet
	[taille du nom de fichier04,  66 69 6C 65 filename, 03nbre d'apdu envoyé, 01taille du dernier apdu, dataApdu1(127 octets max) ]
	*/
	void writeFileToCard( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if(buffer[(short)2]==0){
			Util.arrayCopy(buffer,(short)4,tableFile,(short)0,(short)(buffer[4]+1));
		}
		if(buffer[(short)2]==1){
			Util.arrayCopy(buffer,(short)5,tableFile,(short)(tableFile[0]+3+buffer[3]*DATAMAXSIZE),(short)(buffer[4]));
		}
		if(buffer[(short)2]==2){
			tableFile[(short)(tableFile[0]+1)]=buffer[(short)3];
			tableFile[(short)(tableFile[0]+2)]=buffer[(short)4];
			tableFile[(short)(tableFile[0]+3+((int)buffer[3])*DATAMAXSIZE)]=buffer[(short)5];
		}

		//OFFSET : buffer[0]+3 +buffer[3]*datamaxsize
	}


	void updateWritePIN( APDU apdu ) {
		if (security&&!pinwrite.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		pinwrite.update(buffer,(short)5,(byte)4); 				// from pincode, offset 0, length 4
	}


	void updateReadPIN( APDU apdu ) {
		if (security&&!pinread.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		pinread.update(buffer,(short)5,(byte)4); 				// from pincode, offset 0, length 4
	}

	void displayPINSecurity( APDU apdu ) {
		byte[] buffer = apdu.getBuffer();
		buffer[0]=buffer[1]=(security?(byte)0x01:(byte)0x00);
		apdu.setOutgoingAndSend((short)0,(short)2);
	}


	void desactivateActivatePINSecurity( APDU apdu ) {
		security=!security;
	}

	void enterReadPIN( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if( !pinread.check( buffer, (byte)5, buffer[4] ) )
				ISOException.throwIt( SW_VERIFICATION_FAILED );
	}

	void enterWritePIN( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if( !pinwrite.check( buffer, (byte)5, buffer[4] ) )
				ISOException.throwIt( SW_VERIFICATION_FAILED );
	}


	void readNameFromCard( APDU apdu ) {
		if (security&&!pinread.isValidated() )
	  	ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(name,(byte)1,buffer,(short)0,name[0]);
		apdu.setOutgoingAndSend((short)0,name[0]);
	}

	//Afficher un message a la console
	//Lecture clavier dans une String
	//String to tableau d'octet
	//definir le tableau d'octect qui va contenir l'apdu de Command
	//Le remplir
	//L'envoyer a la carte
	//CLA INS P1 P2 LC Data
	//rien 1   2  3
	void writeNameToCard( APDU apdu ) {
		if (security&&!pinwrite.isValidated() )
	  	ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(buffer,(short)4,name,(short)0,(short)(buffer[4]+1));
	}


}
