/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002,2003, Beneficent
Technology, Inc. (Benetech).

Martus is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later
version with the additions and exceptions described in the
accompanying Martus license file entitled "license.txt".

It is distributed WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, including warranties of fitness of purpose or
merchantability.  See the accompanying Martus License and
GPL license for more details on the required license terms
for this software.

You should have received a copy of the GNU General Public
License along with this program; if not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.

*/

package org.martus.server.main;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.TimerTask;
import java.util.Vector;

import org.martus.amplifier.ServerCallbackInterface;
import org.martus.amplifier.main.MartusAmplifier;
import org.martus.common.LoggerInterface;
import org.martus.common.LoggerToConsole;
import org.martus.common.MartusUtilities;
import org.martus.common.Version;
import org.martus.common.VersionBuildDate;
import org.martus.common.MartusUtilities.FileTooLargeException;
import org.martus.common.MartusUtilities.FileVerificationException;
import org.martus.common.MartusUtilities.InvalidPublicKeyFileException;
import org.martus.common.MartusUtilities.PublicInformationInvalidException;
import org.martus.common.bulletin.BulletinZipUtilities;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MartusSecurity;
import org.martus.common.crypto.MartusCrypto.AuthorizationFailedException;
import org.martus.common.crypto.MartusCrypto.CryptoException;
import org.martus.common.crypto.MartusCrypto.CryptoInitializationException;
import org.martus.common.crypto.MartusCrypto.DecryptionException;
import org.martus.common.crypto.MartusCrypto.InvalidKeyPairFileVersionException;
import org.martus.common.crypto.MartusCrypto.MartusSignatureException;
import org.martus.common.crypto.MartusCrypto.NoKeyPairException;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.FileDatabase;
import org.martus.common.database.ServerFileDatabase;
import org.martus.common.database.Database.RecordHiddenException;
import org.martus.common.network.MartusSecureWebServer;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.FieldDataPacket;
import org.martus.common.packet.Packet;
import org.martus.common.packet.UniversalId;
import org.martus.common.packet.Packet.InvalidPacketException;
import org.martus.common.packet.Packet.SignatureVerificationException;
import org.martus.common.packet.Packet.WrongPacketTypeException;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.common.utilities.MartusServerUtilities.DuplicatePacketException;
import org.martus.common.utilities.MartusServerUtilities.SealedPacketExistsException;
import org.martus.server.foramplifiers.ServerForAmplifiers;
import org.martus.server.forclients.ServerForClients;
import org.martus.server.formirroring.ServerForMirroring;
import org.martus.util.Base64;
import org.martus.util.InputStreamWithSeek;
import org.martus.util.UnicodeReader;
import org.martus.util.Base64.InvalidBase64Exception;
import org.martus.util.xmlrpc.XmlRpcThread;

public class MartusServer implements NetworkInterfaceConstants, ServerCallbackInterface
{
	public static void main(String[] args)
	{
		try
		{
			displayVersion();
			System.out.println("Initializing...this will take a few seconds...");
			MartusServer server = new MartusServer(getDefaultDataDirectory());

			server.processCommandLine(args);
			server.deleteRunningFile();

			if(server.anyUnexpectedFilesOrFoldersInStartupDirectory())
				System.exit(EXIT_UNEXPECTED_FILE_STARTUP);
			
			if(!server.hasAccount())
			{
				System.out.println("***** Key pair file not found *****");
				System.exit(EXIT_KEYPAIR_FILE_MISSING);
			}

			char[] passphrase = server.insecurePassword;
			if(passphrase == null)
				passphrase = server.getPassphraseFromConsole(server);
			server.loadAccount(passphrase);
			server.initalizeDatabase();
			server.verifyAndLoadConfigurationFiles();
			server.displayStatistics();

			System.out.println("Setting up sockets (this may take up to a minute or longer)...");
		
			server.initializeServerForClients();
			server.initializeServerForMirroring();
			server.initializeServerForAmplifiers();
			server.initalizeAmplifier(passphrase);

			if(!server.deleteStartupFiles())
				System.exit(EXIT_STARTUP_DIRECTORY_NOT_EMPTY);
			
			server.startBackgroundTimers();
			
			MartusServer.writeSyncFile(server.getRunningFile());
			if(!server.isAmplifierEnabled() && !server.isAmplifierListenerEnabled() &&
			   !server.isClientListenerEnabled() && !server.isMirrorListenerEnabled())
			{				
				System.out.println("No listeners or web amplifier enabled... Exiting.");
				server.serverExit(EXIT_NO_LISTENERS);
			}
			System.out.println("Waiting for connection...");
		}
		catch(CryptoInitializationException e) 
		{
			System.out.println("Crypto Initialization Exception" + e);
			System.exit(EXIT_CRYPTO_INITIALIZATION);			
		}
		catch (AuthorizationFailedException e)
		{
			System.out.println("Invalid password: " + e);
			System.exit(EXIT_INVALID_PASSWORD);
		}
		catch (UnknownHostException e)
		{
			System.out.println("ipAddress invalid: " + e);
			System.exit(EXIT_INVALID_IPADDRESS);
		}
		catch (Exception e)
		{
			System.out.println("MartusServer.main: " + e);
			System.exit(EXIT_UNEXPECTED_EXCEPTION);
		}
			
	}

	MartusServer(File dir) throws 
					CryptoInitializationException, IOException, InvalidPublicKeyFileException, PublicInformationInvalidException
	{
		this(dir, new LoggerToConsole());
	}

	protected MartusServer(File dir, LoggerInterface loggerToUse) throws 
					MartusCrypto.CryptoInitializationException, IOException, InvalidPublicKeyFileException, PublicInformationInvalidException
	{
		this(dir, loggerToUse, new MartusSecurity());
	}

	public MartusServer(File dir, LoggerInterface loggerToUse, MartusCrypto securityToUse) throws 
					MartusCrypto.CryptoInitializationException, IOException, InvalidPublicKeyFileException, PublicInformationInvalidException
	{
		dataDirectory = dir;
		setLogger(loggerToUse);
		security = securityToUse;
		MartusSecureWebServer.security = getSecurity();
		
		getTriggerDirectory().mkdirs();
		getStartupConfigDirectory().mkdirs();
		serverForClients = new ServerForClients(this);
		serverForMirroring = new ServerForMirroring(this, getLogger());
		serverForAmplifiers = new ServerForAmplifiers(this, getLogger());
		amp = new MartusAmplifier(this);
		failedUploadRequestsPerIp = new Hashtable();
	}
	
	public boolean anyUnexpectedFilesOrFoldersInStartupDirectory()
	{
		Vector startupFilesWeExpect = getDeleteOnStartupFiles();
		Vector startupFoldersWeExpect = getDeleteOnStartupFolders();
		File[] allFilesAndFoldersInStartupDirectory = getStartupConfigDirectory().listFiles();
		for(int i = 0; i<allFilesAndFoldersInStartupDirectory.length; ++i)
		{
			File file = allFilesAndFoldersInStartupDirectory[i];
			if(file.isFile()&&!startupFilesWeExpect.contains(file))
			{	
				log("Startup File not expected =" + file.getAbsolutePath());
				return true;
			}
			if(file.isDirectory()&&!startupFoldersWeExpect.contains(file))
			{	
				log("Startup Folder not expected =" + file.getAbsolutePath());
				return true;
			}
		}
		return false;
	}
	
	
	protected void startBackgroundTimers()
	{
		MartusUtilities.startTimer(new ShutdownRequestMonitor(), shutdownRequestIntervalMillis);
		MartusUtilities.startTimer(new UploadRequestsMonitor(), magicWordsGuessIntervalMillis);
		if(isAmplifierEnabled())
			MartusUtilities.startTimer(new SyncAmplifierWithServersMonitor(), amplifierDataSynchIntervalMillis);
	}

	private void displayServerPublicCode() throws InvalidBase64Exception
	{
		System.out.print("Server Public Code: ");
		String accountId = getAccountId();
		String publicCode = MartusCrypto.computePublicCode(accountId);
		System.out.println(MartusCrypto.formatPublicCode(publicCode));
		System.out.println();
	}

	private void displayComplianceStatement()
	{
		System.out.println();
		System.out.println("Server Compliance Statement:");
		System.out.println("---");
		System.out.println(complianceStatement);
		System.out.println("---");
	}

	public void verifyAndLoadConfigurationFiles() throws Exception
	{
		verifyConfigurationFiles();
		loadConfigurationFiles();
	}

	protected void displayStatistics() throws InvalidBase64Exception
	{
		displayComplianceStatement();
		displayServerPublicCode();
	}
	
	public void verifyConfigurationFiles()
	{
		if(isClientListenerEnabled())
			serverForClients.verifyConfigurationFiles();
		if(isMirrorListenerEnabled())
			serverForMirroring.verifyConfigurationFiles();
		if(isAmplifierListenerEnabled())
			serverForAmplifiers.verifyConfigurationFiles();
	}

	public void loadConfigurationFiles() throws Exception
	{
		if(isClientListenerEnabled())
			serverForClients.loadConfigurationFiles();
		if(isMirrorListenerEnabled())
			serverForMirroring.loadConfigurationFiles();
		if(isAmplifierListenerEnabled())
			serverForAmplifiers.loadConfigurationFiles();

		//Tests will fail if compliance isn't last.
		loadHiddenPacketsFile();
		loadComplianceStatementFile();
	}

	public Database getDatabase()
	{
		return database;
	}
	
	public void setDatabase(Database databaseToUse)
	{
		database = databaseToUse;
	}
	
	public void setAmpIpAddress(String ampIpAddress)
	{
		this.ampIpAddress = ampIpAddress;
	}

	public String getAmpIpAddress()
	{
		return ampIpAddress;
	}

	private static void setListenersIpAddress(String listenersIpAddress)
	{
		MartusServer.listenersIpAddress = listenersIpAddress;
	}

	private static String getListenersIpAddress()
	{
		return listenersIpAddress;
	}

	public void setLogger(LoggerInterface logger)
	{
		this.logger = logger;
	}

	public LoggerInterface getLogger()
	{
		return logger;
	}

	public MartusCrypto getSecurity()
	{
		return security;
	}
	
	public boolean isSecureMode()
	{
		return secureMode;
	}
	
	public void enterSecureMode()
	{
		secureMode = true;
	}
	
	
	private void setAmplifierEnabled(boolean amplifierEnabled)
	{
		this.amplifierEnabled = amplifierEnabled;
	}

	private boolean isAmplifierEnabled()
	{
		return amplifierEnabled;
	}

	public void setClientListenerEnabled(boolean clientListenerEnabled)
	{
		this.clientListenerEnabled = clientListenerEnabled;
	}

	private boolean isClientListenerEnabled()
	{
		return clientListenerEnabled;
	}

	private void setMirrorListenerEnabled(boolean mirrorListenerEnabled)
	{
		this.mirrorListenerEnabled = mirrorListenerEnabled;
	}

	private boolean isMirrorListenerEnabled()
	{
		return mirrorListenerEnabled;
	}

	public void setAmplifierListenerEnabled(boolean amplifierListenerEnabled)
	{
		this.amplifierListenerEnabled = amplifierListenerEnabled;
	}

	private boolean isAmplifierListenerEnabled()
	{
		return amplifierListenerEnabled;
	}

	protected boolean hasAccount()
	{
		return getKeyPairFile().exists();
	}
	
	protected void loadAccount(char[] passphrase) throws AuthorizationFailedException, InvalidKeyPairFileVersionException, IOException
	{
		FileInputStream in = new FileInputStream(getKeyPairFile());
		readKeyPair(in, passphrase);
		in.close();
		System.out.println("Passphrase correct.");			
	}
	
	public String getAccountId()
	{
		return security.getPublicKeyString();
	}
	
	public String ping()
	{
		log("ping request");		
		return NetworkInterfaceConstants.VERSION;
	}

	public Vector getServerInformation()
	{
		log("getServerInformation");
			
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
				
		Vector result = new Vector();
		try
		{
			String publicKeyString = security.getPublicKeyString();
			byte[] publicKeyBytes = Base64.decode(publicKeyString);
			ByteArrayInputStream in = new ByteArrayInputStream(publicKeyBytes);
			byte[] sigBytes = security.createSignatureOfStream(in);
			
			result.add(NetworkInterfaceConstants.OK);
			result.add(publicKeyString);
			result.add(Base64.encode(sigBytes));
			log("getServerInformation: Exit OK");
		}
		catch(Exception e)
		{
			result.add(NetworkInterfaceConstants.SERVER_ERROR);
			result.add(e.toString());
			log("getServerInformation SERVER ERROR" + e);			
		}
		return result;
	}
	
	public String requestUploadRights(String clientId, String tryMagicWord)
	{
		boolean uploadGranted = false;

		if(serverForClients.isValidMagicWord(tryMagicWord))
			uploadGranted = true;
			
		if(!areUploadRequestsAllowedForCurrentIp())
		{
			if(!uploadGranted)
				incrementFailedUploadRequestsForCurrentClientIp();
			return NetworkInterfaceConstants.SERVER_ERROR;
		}

		if( isClientBanned(clientId) )
			return NetworkInterfaceConstants.REJECTED;
			
		if( isShutdownRequested() )
			return NetworkInterfaceConstants.SERVER_DOWN;
			
		if(tryMagicWord.length() == 0 && canClientUpload(clientId))
			return NetworkInterfaceConstants.OK;
		
		if(!uploadGranted)
		{
			log("requestUploadRights: Rejected " + getPublicCode(clientId) + " tryMagicWord=" +tryMagicWord);
			incrementFailedUploadRequestsForCurrentClientIp();
			return NetworkInterfaceConstants.REJECTED;
		}
		log("requestUploadRights granted to: " + getPublicCode(clientId) + " with magicword=" + tryMagicWord);
			
		serverForClients.allowUploads(clientId);
		return NetworkInterfaceConstants.OK;
	}
	
	
	public String uploadBulletinChunk(String authorAccountId, String bulletinLocalId, int totalSize, int chunkOffset, int chunkSize, String data, String signature)
	{
		log("uploadBulletinChunk");
		
		if(isClientBanned(authorAccountId) )
			return NetworkInterfaceConstants.REJECTED;
		
		if( isShutdownRequested() )
			return NetworkInterfaceConstants.SERVER_DOWN;
		
		String signedString = authorAccountId + "," + bulletinLocalId + "," +
					Integer.toString(totalSize) + "," + Integer.toString(chunkOffset) + "," +
					Integer.toString(chunkSize) + "," + data;
		if(!isSignatureCorrect(signedString, signature, authorAccountId))
		{
			log("  returning SIG_ERROR");
			log("Account: " + MartusCrypto.formatAccountIdForLog(authorAccountId));
			log("signedString: " + signedString.toString());
			log("signature: " + signature);
			return NetworkInterfaceConstants.SIG_ERROR;
		}
		
		String result = putBulletinChunk(authorAccountId, authorAccountId, bulletinLocalId,
									totalSize, chunkOffset, chunkSize, data);
		return result;
	}


	public String putBulletinChunk(String uploaderAccountId, String authorAccountId, String bulletinLocalId,
		int totalSize, int chunkOffset, int chunkSize, String data) 
	{
		{
			StringBuffer logMsg = new StringBuffer();
			logMsg.append("putBulletinChunk");
			logMsg.append("  " + getClientAliasForLogging(authorAccountId) + " " + bulletinLocalId);
			logMsg.append("  Total Size=" + totalSize + ", Offset=" + chunkOffset);
			if(chunkSize != NetworkInterfaceConstants.MAX_CHUNK_SIZE)
				logMsg.append(" Last Chunk = " + chunkSize);
			
			log(logMsg.toString());
		}
		
		if(isClientBanned(authorAccountId) || !canClientUpload(authorAccountId))
		{
			log("putBulletinChunk REJECTED");
			return NetworkInterfaceConstants.REJECTED;
		}
		
		if( isShutdownRequested() )
		{
			log(" returning SERVER_DOWN");
			return NetworkInterfaceConstants.SERVER_DOWN;
		}
		
		UniversalId uid = UniversalId.createFromAccountAndLocalId(authorAccountId, bulletinLocalId);
		DatabaseKey key = new DatabaseKey(uid);
		File interimZipFile;
		try 
		{
			interimZipFile = getDatabase().getIncomingInterimFile(key);
		} 
		catch (IOException e) 
		{
			log("putBulletinChunk Error creating interim file." + e.getMessage());
			return NetworkInterfaceConstants.SERVER_ERROR;
		} 
		catch (RecordHiddenException e)
		{
			// TODO: Should return a more specific error code
			log("putBulletinChunk for hidden file " + uid.getLocalId());
			return NetworkInterfaceConstants.INVALID_DATA;
		}
		
		if(chunkSize > NetworkInterfaceConstants.MAX_CHUNK_SIZE)
		{
			interimZipFile.delete();
			log("putBulletinChunk INVALID_DATA (> MAX_CHUNK_SIZE)");
			return NetworkInterfaceConstants.INVALID_DATA;
		}			
		
		if(chunkOffset == 0)
		{
			//this log made no sence. log("putBulletinChunk: restarting at zero");
			interimZipFile.delete();
		}
		
		double oldFileLength = interimZipFile.length();
		if(oldFileLength != chunkOffset)
		{
			interimZipFile.delete();
			log("putBulletinChunk INVALID_DATA (!= file length)");
			return NetworkInterfaceConstants.INVALID_DATA;
		}
		
		if(oldFileLength + chunkSize > totalSize)
		{
			interimZipFile.delete();
			log("putBulletinChunk INVALID_DATA (> totalSize)");
			return NetworkInterfaceConstants.INVALID_DATA;
		}			
		
		StringReader reader = null;
		FileOutputStream out = null;
		try 
		{
			reader = new StringReader(data);
			out = new FileOutputStream(interimZipFile.getPath(), true);
			Base64.decode(reader, out);
			out.close();
			reader.close();
		} 
		catch(Exception e)
		{
			try 
			{
				if(out != null)
					out.close();
			} 
			catch (IOException nothingWeCanDo) 
			{
			}
			if(reader != null)
				reader.close();
			interimZipFile.delete();
			log("putBulletinChunk INVALID_DATA " + e);
			return NetworkInterfaceConstants.INVALID_DATA;
		}
		
		String result = NetworkInterfaceConstants.CHUNK_OK;
		double newFileLength = interimZipFile.length();
		if(chunkSize != newFileLength - oldFileLength)
		{
			interimZipFile.delete();
			log("putBulletinChunk INVALID_DATA (chunkSize != actual dataSize)");
			return NetworkInterfaceConstants.INVALID_DATA;
		}			
		
		if(newFileLength >= totalSize)
		{
			//log("entering saveUploadedBulletinZipFile");
			try 
			{
				result = saveUploadedBulletinZipFile(authorAccountId, bulletinLocalId, interimZipFile);
			} catch (Exception e) 
			{
				log("Exception =" + e);
				e.printStackTrace();
			}
			//log("returned from saveUploadedBulletinZipFile result =" + result);
			interimZipFile.delete();
		}
		
		log("putBulletinChunk: Exit " + result);
		return result;
	}


	public Vector getBulletinChunk(String myAccountId, String authorAccountId, String bulletinLocalId,
		int chunkOffset, int maxChunkSize) 
	{
		{
			StringBuffer logMsg = new StringBuffer();
			logMsg.append("getBulletinChunk remote: " + getClientAliasForLogging(myAccountId));
			logMsg.append(" local: " + getClientAliasForLogging(authorAccountId) + " " + bulletinLocalId);
			logMsg.append("  Offset=" + chunkOffset + ", Max=" + maxChunkSize);
			log(logMsg.toString());
		}
		
		if(isClientBanned(myAccountId) )
			return returnSingleResponseAndLog( " returning REJECTED", NetworkInterfaceConstants.REJECTED );
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );

		DatabaseKey headerKey =	findHeaderKeyInDatabase(authorAccountId, bulletinLocalId);
		if(headerKey == null)
			return returnSingleResponseAndLog( " returning NOT_FOUND", NetworkInterfaceConstants.NOT_FOUND );

		if(!myAccountId.equals(authorAccountId))
		{
			try 
			{
				String hqAccountId = getBulletinHQAccountId(headerKey);
				if(!myAccountId.equals(hqAccountId))
					return returnSingleResponseAndLog( " returning NOTYOURBULLETIN", NetworkInterfaceConstants.NOTYOURBULLETIN );
			} 
			catch (SignatureVerificationException e) 
			{
					return returnSingleResponseAndLog( " returning SIG ERROR", NetworkInterfaceConstants.SIG_ERROR );
			} 
			catch (Exception e) 
			{
				return returnSingleResponseAndLog( " returning SERVER_ERROR: " + e, NetworkInterfaceConstants.SERVER_ERROR );
			} 
		}

		Vector result = getBulletinChunkWithoutVerifyingCaller(
					authorAccountId, bulletinLocalId,
					chunkOffset, maxChunkSize);
		
		
		log("getBulletinChunk exit: " + result.get(0));
		return result;
	}


	public Vector listMySealedBulletinIds(String clientId, Vector retrieveTags)
	{
		log("listMySealedBulletinIds " + getClientAliasForLogging(clientId));
		
		if(isClientBanned(clientId) )
			return returnSingleResponseAndLog("  returning REJECTED", NetworkInterfaceConstants.REJECTED);
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
		
		SummaryCollector summaryCollector = new MySealedSummaryCollector(getDatabase(), clientId, retrieveTags);
		Vector summaries = summaryCollector.getSummaries();
		String resultCode = (String)summaries.get(0);
		summaries.remove(0);

		Vector result = new Vector();
		result.add(resultCode);
		result.add(summaries);
		log("listMySealedBulletinIds: Exit");
		return result;
	}

	public Vector listMyDraftBulletinIds(String authorAccountId, Vector retrieveTags)
	{
		log("listMyDraftBulletinIds " + getClientAliasForLogging(authorAccountId));
			
		if(isClientBanned(authorAccountId) )
			return returnSingleResponseAndLog("  returning REJECTED", NetworkInterfaceConstants.REJECTED);
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
		
		SummaryCollector summaryCollector = new MyDraftSummaryCollector(getDatabase(), authorAccountId, retrieveTags);
		Vector summaries = summaryCollector.getSummaries();

		String resultCode = (String)summaries.get(0);
		summaries.remove(0);
		Vector result = new Vector();
		result.add(resultCode);
		result.add(summaries);

		log("listMyDraftBulletinIds: Exit");
		return result;
	}

	public Vector listFieldOfficeSealedBulletinIds(String hqAccountId, String authorAccountId, Vector retrieveTags)
	{
		log("listFieldOfficeSealedBulletinIds " + getClientAliasForLogging(hqAccountId));
			
		if(isClientBanned(hqAccountId) )
			return returnSingleResponseAndLog("  returning REJECTED", NetworkInterfaceConstants.REJECTED);
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
		
		SummaryCollector summaryCollector = new FieldOfficeSealedSummaryCollector(getDatabase(), hqAccountId, authorAccountId, retrieveTags);
		Vector summaries = summaryCollector.getSummaries();

		String resultCode = (String)summaries.get(0);
		summaries.remove(0);

		Vector result = new Vector();
		result.add(resultCode);
		result.add(summaries);

		log("listFieldOfficeSealedBulletinIds: Exit");
		return result;	
	}

	public Vector listFieldOfficeDraftBulletinIds(String hqAccountId, String authorAccountId, Vector retrieveTags)
	{
		log("listFieldOfficeDraftBulletinIds " + getClientAliasForLogging(hqAccountId));

		if(isClientBanned(hqAccountId) )
			return returnSingleResponseAndLog( " returning REJECTED", NetworkInterfaceConstants.REJECTED );
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
			
		SummaryCollector summaryCollector = new FieldOfficeDraftSummaryCollector(getDatabase(), hqAccountId, authorAccountId, retrieveTags);
		Vector summaries = summaryCollector.getSummaries();

		String resultCode = (String)summaries.get(0);
		summaries.remove(0);
		Vector result = new Vector();
		result.add(resultCode);
		result.add(summaries);

		log("listFieldOfficeDraftBulletinIds: Exit");
		return result;
	}

	public Vector listFieldOfficeAccounts(String hqAccountIdToUse)
	{

		class FieldOfficeAccountCollector implements Database.PacketVisitor
		{
			FieldOfficeAccountCollector(String hqAccountIdToUse)
			{
				hqAccountId = hqAccountIdToUse;
				accounts = new Vector();
				accounts.add(NetworkInterfaceConstants.OK);
			}
			
			public void visit(DatabaseKey key)
			{
				if(!BulletinHeaderPacket.isValidLocalId(key.getLocalId()))
					return;
				try
				{
					BulletinHeaderPacket bhp = loadBulletinHeaderPacket(getDatabase(), key);
					if(bhp.getHQPublicKey().equals(hqAccountId))
					{
						String packetAccountId = bhp.getAccountId();
						if(!accounts.contains(packetAccountId))
							accounts.add(packetAccountId);
					}
				}
				catch(Exception e)
				{
					log("FieldOfficeAccountCollector:Visit " + e);
					accounts.set(0, NetworkInterfaceConstants.SERVER_ERROR);
				}
			}
			
			public Vector getAccounts()
			{
				return accounts;
			}
			String hqAccountId;
			Vector accounts;
		}	

		log("listFieldOfficeAccounts " + getClientAliasForLogging(hqAccountIdToUse));
			
		if(isClientBanned(hqAccountIdToUse) )
			return returnSingleResponseAndLog("  returning REJECTED", NetworkInterfaceConstants.REJECTED);
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog("  returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN);

		FieldOfficeAccountCollector visitor = new FieldOfficeAccountCollector(hqAccountIdToUse);
		getDatabase().visitAllRecords(visitor);
	
		log("listFieldOfficeAccounts: Exit");
		return visitor.getAccounts();	
	}
	
	public String deleteDraftBulletins(String accountId, String[] localIds)
	{
		if(isClientBanned(accountId) )
			return REJECTED;
		
		if( isShutdownRequested() )
			return SERVER_DOWN;
			
		String result = OK;
		for (int i = 0; i < localIds.length; i++)
		{
			UniversalId uid = UniversalId.createFromAccountAndLocalId(accountId, localIds[i]);
			try
			{
				DatabaseKey key = DatabaseKey.createDraftKey(uid);
				BulletinHeaderPacket bhp = new BulletinHeaderPacket(uid);
				InputStreamWithSeek in = getDatabase().openInputStream(key, security);
				bhp.loadFromXml(in, null, security);
				in.close();

				MartusUtilities.deleteBulletinFromDatabase(bhp, getDatabase(), security);
				DatabaseKey burKey = MartusServerUtilities.getBurKey(key);
				getDatabase().discardRecord(burKey);			
			}
			catch (Exception e)
			{
				log("deleteDraftBulletins: " + e);
				result = INCOMPLETE;
			}
		}
		return result;
	}
	
	public String putContactInfo(String accountId, Vector contactInfo)
	{
		log("putContactInfo " + getClientAliasForLogging(accountId));

		if(isClientBanned(accountId) || !canClientUpload(accountId))
			return NetworkInterfaceConstants.REJECTED;
		
		if( isShutdownRequested() )
			return NetworkInterfaceConstants.SERVER_DOWN;
			
		String result = NetworkInterfaceConstants.INVALID_DATA;
		if(contactInfo == null)
			return result;
		if(contactInfo.size() <= 3)
			return result;
		String publicKey = (String)contactInfo.get(0);
		if(!publicKey.equals(accountId))
			return result;
		int contentSize = ((Integer)(contactInfo.get(1))).intValue();
		if(contentSize + 3 != contactInfo.size())
			return result;

		if(!security.verifySignatureOfVectorOfStrings(contactInfo, publicKey))
			return NetworkInterfaceConstants.SIG_ERROR;

		try
		{
			File contactFile = getDatabase().getContactInfoFile(accountId);
			MartusServerUtilities.writeContatctInfo(accountId, contactInfo, contactFile);
		}
		catch (IOException e)
		{
			log("putContactInfo Error" + e);
			return NetworkInterfaceConstants.SERVER_ERROR;
		}
		return NetworkInterfaceConstants.OK;
	}

	public Vector getContactInfo(String accountId)
	{
		Vector results = new Vector();
		File contactFile;
		try
		{
			contactFile = database.getContactInfoFile(accountId);
			if(!contactFile.exists())
			{
				results.add(NetworkInterfaceConstants.NOT_FOUND);
				return results;
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
			results.add(NetworkInterfaceConstants.NOT_FOUND);
			return results;
		}
		
		try
		{
			Vector contactInfo = MartusServerUtilities.getContactInfo(contactFile);
			if(!security.verifySignatureOfVectorOfStrings(contactInfo, accountId))
			{
				String accountInfo = MartusSecurity.formatAccountIdForLog(accountId);
				log("getContactInfo: "+ accountInfo +": Signature failed");
				results.add(NetworkInterfaceConstants.SIG_ERROR);
				return results;
			}
			results.add(NetworkInterfaceConstants.OK);
			results.add(contactInfo);
			return results;
		}
		catch (Exception e1)
		{
			e1.printStackTrace();
			results.add(NetworkInterfaceConstants.SERVER_ERROR);
			return results;
		}
	}

	public Vector getNews(String accountId, String versionLabel, String versionBuildDate)
	{
		Vector result = new Vector();
		Vector items = new Vector();
		{
			String loggingData = "getNews: " + getClientAliasForLogging(accountId);
			if(versionLabel.length() > 0 && versionBuildDate.length() > 0)
				loggingData = loggingData +", " + versionLabel + ", " + versionBuildDate;

			log(loggingData);
		}		

		if(isClientBanned(accountId))
		{
			final String bannedText = "Your account has been blocked from accessing this server. " + 
					"Please contact the Server Policy Administrator for more information.";
			items.add(bannedText);
		}

		result.add(OK);
		result.add(items);
		return result;
	}

	public void setComplianceStatement(String statement)
	{
		complianceStatement = statement;
	}

	public Vector getServerCompliance()
	{
		log("getServerCompliance");
		Vector result = new Vector();
		result.add(OK);
		Vector compliance = new Vector();
		compliance.add(complianceStatement);
		result.add(compliance);
		return result;
	}	

	public File getContactInfoFileForAccount(String accountId) throws
		IOException
	{
		return getDatabase().getContactInfoFile(accountId);
	}

	public Vector downloadFieldDataPacket(String authorAccountId, String bulletinLocalId, String packetLocalId, String myAccountId, String signature)
	{
		log("downloadFieldOfficeDataPacket: " + getClientAliasForLogging(authorAccountId) + "  " + 
				bulletinLocalId + "  packet " + packetLocalId + " requested by: " + 
				getClientAliasForLogging(myAccountId));
		
		if(isClientBanned(myAccountId) )
			return returnSingleResponseAndLog( " returning REJECTED", NetworkInterfaceConstants.REJECTED );
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
	
		Vector result = new Vector();

		String signedString = authorAccountId + "," + bulletinLocalId + "," + packetLocalId + "," + myAccountId;
		if(!isSignatureCorrect(signedString, signature, myAccountId))
		{
			log("  returning SIG_ERROR");
			log("Account: " + MartusCrypto.formatAccountIdForLog(authorAccountId));
			log("signedString: " + signedString.toString());
			log("signature: " + signature);
			return returnSingleResponseAndLog("", NetworkInterfaceConstants.SIG_ERROR);
		}
		
		result = getPacket(myAccountId, authorAccountId, bulletinLocalId, packetLocalId);
		
		log("downloadFieldDataPacket: Exit");
		return result;
	}


	public Vector getPacket(String myAccountId, String authorAccountId, String bulletinLocalId,
		String packetLocalId) 
	{
		Vector result = new Vector();
		
		if(isClientBanned(myAccountId) )
			return returnSingleResponseAndLog( " returning REJECTED", NetworkInterfaceConstants.REJECTED );
		
		if( isShutdownRequested() )
			return returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
		
		if(!FieldDataPacket.isValidLocalId(packetLocalId))
		{
			return returnSingleResponseAndLog( "  attempt to download non-fielddatapacket: " + packetLocalId, NetworkInterfaceConstants.INVALID_DATA );
		}
		
		Database db = getDatabase();
		
		UniversalId headerUid = UniversalId.createFromAccountAndLocalId(authorAccountId, bulletinLocalId);
		DatabaseKey headerKey = DatabaseKey.createSealedKey(headerUid);
		
		if(!db.doesRecordExist(headerKey))
			headerKey.setDraft();
		
		if(!db.doesRecordExist(headerKey))
		{
			return returnSingleResponseAndLog( "  header packet not found", NetworkInterfaceConstants.NOT_FOUND );
		}
		
		UniversalId dataPacketUid = UniversalId.createFromAccountAndLocalId(authorAccountId, packetLocalId);
		DatabaseKey dataPacketKey = new DatabaseKey(dataPacketUid);
		if(headerKey.isDraft())
			dataPacketKey.setDraft();
		else
			dataPacketKey.setSealed();
			
		if(!db.doesRecordExist(dataPacketKey))
		{
			return returnSingleResponseAndLog( "  data packet not found", NetworkInterfaceConstants.NOT_FOUND );
		}
		
		try
		{
			if(!myAccountId.equals(authorAccountId) && 
					!myAccountId.equals(getBulletinHQAccountId(headerKey)) )
			{
				return returnSingleResponseAndLog( "  neither author nor HQ account", NetworkInterfaceConstants.NOTYOURBULLETIN );
			}
			
			String packetXml = db.readRecord(dataPacketKey, security);
		
			result.add(NetworkInterfaceConstants.OK);
			result.add(packetXml);
			return result;
		}
		catch(Exception e)
		{
			//TODO: Make sure this has a test!
			log("  error loading " + e);
			result.clear();
			result.add(NetworkInterfaceConstants.SERVER_ERROR);
			return result;
		}
	}

	public String authenticateServer(String tokenToSign)
	{
		log("authenticateServer");
		try 
		{
			InputStream in = new ByteArrayInputStream(Base64.decode(tokenToSign));
			byte[] sig = security.createSignatureOfStream(in);
			return Base64.encode(sig);
		} 
		catch(MartusSignatureException e) 
		{
			log("SERVER_ERROR: " + e);
			return NetworkInterfaceConstants.SERVER_ERROR;
		} 
		catch(InvalidBase64Exception e) 
		{
			log("INVALID_DATA: " + e);
			return NetworkInterfaceConstants.INVALID_DATA;
		}
	}
	
	// end MartusServerInterface interface

	public boolean canClientUpload(String clientId)
	{
		return serverForClients.canClientUpload(clientId);
	}
	
	public boolean isClientBanned(String clientId)
	{
		return serverForClients.isClientBanned(clientId);
	}

	public String getPublicCode(String clientId) 
	{
		String formattedCode = "";
		try 
		{
			String publicCode = MartusCrypto.computePublicCode(clientId);
			formattedCode = MartusCrypto.formatPublicCode(publicCode);
		} 
		catch(InvalidBase64Exception e) 
		{
		}
		return formattedCode;
	}
	
	public void loadComplianceStatementFile() throws IOException
	{
		try
		{
			UnicodeReader reader = new UnicodeReader(getComplianceFile());
			setComplianceStatement(reader.readAll(100));
			reader.close();
		}
		catch (IOException e)
		{
			log("Missing or unable to read file: " + getComplianceFile().getAbsolutePath());
			throw e;
		}
	}

	public static boolean keyBelongsToClient(DatabaseKey key, String clientId)
	{
		return clientId.equals(key.getAccountId());
	}

	void readKeyPair(InputStream in, char[] passphrase) throws 
		IOException,
		MartusCrypto.AuthorizationFailedException,
		MartusCrypto.InvalidKeyPairFileVersionException
	{
		security.readKeyPair(in, passphrase);
	}
	
	void writeKeyPair(OutputStream out, char[] passphrase) throws 
		IOException
	{
		security.writeKeyPair(out, passphrase);
	}
	
	public static String getDefaultDataDirectoryPath()
	{
		String dataDirectory = null;
		if(Version.isRunningUnderWindows())
		{
			dataDirectory = "C:/MartusServer/";
		}
		else
		{
			dataDirectory = "/var/MartusServer/";
		}
		return dataDirectory;
	}
	
	public static File getDefaultDataDirectory()
	{
		File file = new File(MartusServer.getDefaultDataDirectoryPath());
		if(!file.exists())
		{
			file.mkdirs();
		}
		
		return file;
	}
	
	public static String getKeypairFilename()
	{
		return KEYPAIRFILENAME;
	}
	
	private Vector returnSingleResponseAndLog( String message, String responseCode )
	{
		if( message.length() > 0 )
			log( message.toString());
		
		Vector response = new Vector();
		response.add( responseCode );
		
		return response;
		
	}
	
	public Vector getBulletinChunkWithoutVerifyingCaller(String authorAccountId, String bulletinLocalId,
				int chunkOffset, int maxChunkSize)
	{
		DatabaseKey headerKey =	findHeaderKeyInDatabase(authorAccountId, bulletinLocalId);
		if(headerKey == null)
			return returnSingleResponseAndLog("getBulletinChunkWithoutVerifyingCaller:  NOT_FOUND ", NetworkInterfaceConstants.NOT_FOUND);
		
		try
		{
			return buildBulletinChunkResponse(headerKey, chunkOffset, maxChunkSize);
		}
		catch(RecordHiddenException e)
		{
			// TODO: Should return more specific error code
			return returnSingleResponseAndLog("getBulletinChunkWithoutVerifyingCaller:  SERVER_ERROR " + e, NetworkInterfaceConstants.SERVER_ERROR);
		}
		catch(Exception e)
		{
			return returnSingleResponseAndLog("getBulletinChunkWithoutVerifyingCaller:  SERVER_ERROR " + e, NetworkInterfaceConstants.SERVER_ERROR);
		}
	}


	public DatabaseKey findHeaderKeyInDatabase(String authorAccountId,String bulletinLocalId) 
	{
		UniversalId uid = UniversalId.createFromAccountAndLocalId(authorAccountId, bulletinLocalId);
		DatabaseKey headerKey = new DatabaseKey(uid);
		headerKey.setSealed();
		if(getDatabase().doesRecordExist(headerKey))
			return headerKey;

		headerKey.setDraft();
		if(getDatabase().doesRecordExist(headerKey))
			return headerKey;

		return null;
	}

	protected String saveUploadedBulletinZipFile(String authorAccountId, String bulletinLocalId, File zipFile) 
	{
		String result = NetworkInterfaceConstants.OK;
		
		BulletinHeaderPacket bhp = null;
		try
		{
			Database db = getDatabase();
			bhp = MartusServerUtilities.saveZipFileToDatabase(db, authorAccountId, zipFile, security);
		}
		catch (DuplicatePacketException e)
		{
			log("saveUpload DUPLICATE: " + e.getMessage());
			result =  NetworkInterfaceConstants.DUPLICATE;
		}
		catch (SealedPacketExistsException e)
		{
			log("saveUpload SEALED_EXISTS: " + e.getMessage());
			result =  NetworkInterfaceConstants.SEALED_EXISTS;
		}
		catch (Packet.SignatureVerificationException e)
		{
			log("saveUpload SIG_ERROR: " + e);
			result =  NetworkInterfaceConstants.SIG_ERROR;
		}
		catch (Packet.WrongAccountException e)
		{
			log("saveUpload NOTYOURBULLETIN: ");
			result =  NetworkInterfaceConstants.NOTYOURBULLETIN;
		}
		catch (Exception e)
		{
			log("saveUpload INVALID_DATA: " + e);
			result =  NetworkInterfaceConstants.INVALID_DATA;
		}
		if(result != NetworkInterfaceConstants.OK)
			return result;

		try
		{
			String bulletinLocalId1 = bhp.getLocalId();
			String bur = MartusServerUtilities.createBulletinUploadRecord(bulletinLocalId1, security);
			MartusServerUtilities.writeSpecificBurToDatabase(getDatabase(), bhp, bur);
		}
		catch (Exception e)
		{
			log("saveUpload SERVER_ERROR: " + e);
			result =  NetworkInterfaceConstants.SERVER_ERROR;
		} 
		
		return result;
	}

	private String getBulletinHQAccountId(DatabaseKey headerKey) throws
			IOException,
			CryptoException,
			InvalidPacketException,
			WrongPacketTypeException,
			SignatureVerificationException,
			DecryptionException
	{
		BulletinHeaderPacket bhp = loadBulletinHeaderPacket(getDatabase(), headerKey);
		return bhp.getHQPublicKey();
	}
	
	private Vector buildBulletinChunkResponse(DatabaseKey headerKey, int chunkOffset, int maxChunkSize) throws
			FileTooLargeException,
			InvalidPacketException, 
			WrongPacketTypeException, 
			SignatureVerificationException, 
			DecryptionException, 
			NoKeyPairException, 
			CryptoException, 
			FileVerificationException, 
			IOException, 
			RecordHiddenException 
	{
		Vector result = new Vector();
		//log("entering createInterimBulletinFile");
		File tempFile = createInterimBulletinFile(headerKey);
		//log("createInterimBulletinFile done");
		int totalLength = MartusUtilities.getCappedFileLength(tempFile);
		
		int chunkSize = totalLength - chunkOffset;
		if(chunkSize > maxChunkSize)
			chunkSize = maxChunkSize;
			
		byte[] rawData = new byte[chunkSize];
		
		FileInputStream in = new FileInputStream(tempFile);
		in.skip(chunkOffset);
		in.read(rawData);
		in.close();
		
		String zipString = Base64.encode(rawData);
		
		int endPosition = chunkOffset + chunkSize;
		if(endPosition >= totalLength)
		{
			MartusUtilities.deleteInterimFileAndSignature(tempFile);
			result.add(NetworkInterfaceConstants.OK);
		}
		else
		{
			result.add(NetworkInterfaceConstants.CHUNK_OK);
		}
		result.add(new Integer(totalLength));
		result.add(new Integer(chunkSize));
		result.add(zipString);
		log("downloadBulletinChunk: Exit " + result.get(0));
		return result;
	}

	public File createInterimBulletinFile(DatabaseKey headerKey) throws
			CryptoException,
			InvalidPacketException,
			WrongPacketTypeException,
			SignatureVerificationException,
			DecryptionException,
			NoKeyPairException,
			MartusUtilities.FileVerificationException, IOException, RecordHiddenException
	{
		File tempFile = getDatabase().getOutgoingInterimFile(headerKey);
		File tempFileSignature = MartusUtilities.getSignatureFileFromFile(tempFile);
		if(tempFile.exists() && tempFileSignature.exists())
		{
			if(verifyBulletinInterimFile(tempFile, tempFileSignature, security.getPublicKeyString()))
				return tempFile;
		}
		MartusUtilities.deleteInterimFileAndSignature(tempFile);
		BulletinZipUtilities.exportBulletinPacketsFromDatabaseToZipFile(getDatabase(), headerKey, tempFile, security);
		tempFileSignature = MartusUtilities.createSignatureFileFromFile(tempFile, security);
		if(!verifyBulletinInterimFile(tempFile, tempFileSignature, security.getPublicKeyString()))
			throw new MartusUtilities.FileVerificationException();
		log("    Total file size =" + tempFile.length());
		
		return tempFile;
	}

	public boolean verifyBulletinInterimFile(File bulletinZipFile, File bulletinSignatureFile, String accountId)
	{
			try 
			{
				MartusUtilities.verifyFileAndSignature(bulletinZipFile, bulletinSignatureFile, security, accountId);
				return true;
			} 
			catch (MartusUtilities.FileVerificationException e) 
			{
				log("    verifyBulletinInterimFile: " + e);
			}
		return false;	
	}
	
	private boolean isSignatureCorrect(String signedString, String signature, String signerPublicKey)
	{
		try
		{
			ByteArrayInputStream in = new ByteArrayInputStream(signedString.getBytes("UTF-8"));
			return security.isValidSignatureOfStream(signerPublicKey, in, Base64.decode(signature));
		}
		catch(Exception e)
		{
			log("  isSigCorrect exception: " + e);
			return false;
		}
	}

	public String getClientAliasForLogging(String clientId)
	{
		try
		{
			return getDatabase().getFolderForAccount(clientId);
		}
		catch (IOException e)
		{
			return clientId;
		}
	}
	
	private Vector getMainServersDeleteOnStartupFiles()
	{
		Vector startupFiles = new Vector();
		startupFiles.add(getKeyPairFile());
		startupFiles.add(getHiddenPacketsFile());
		startupFiles.add(getComplianceFile());
		return startupFiles;
		
	}
	
	public Vector getDeleteOnStartupFiles()
	{
		Vector startupFiles = new Vector();
		startupFiles.addAll(getMainServersDeleteOnStartupFiles());
		startupFiles.addAll(amp.getDeleteOnStartupFiles());
		startupFiles.addAll(serverForClients.getDeleteOnStartupFiles());
		startupFiles.addAll(serverForAmplifiers.getDeleteOnStartupFiles());
		startupFiles.addAll(serverForMirroring.getDeleteOnStartupFiles());
		return startupFiles;
	}

	public Vector getDeleteOnStartupFolders()
	{
		Vector startupFolders = new Vector();
		startupFolders.addAll(amp.getDeleteOnStartupFolders());
		startupFolders.addAll(serverForAmplifiers.getDeleteOnStartupFolders());
		startupFolders.addAll(serverForMirroring.getDeleteOnStartupFolders());
		return startupFolders;
	}
	
	public boolean deleteStartupFiles()
	{
		if(!isSecureMode())
			return true;

		MartusUtilities.deleteAllFiles(getMainServersDeleteOnStartupFiles());
		amp.deleteAmplifierStartupFiles();
		serverForClients.deleteStartupFiles();
		serverForAmplifiers.deleteStartupFiles();
		serverForMirroring.deleteStartupFiles();
		
		File startupDir = getStartupConfigDirectory();
		File[] remainingStartupFiles = startupDir.listFiles();
		if(remainingStartupFiles.length != 0)
		{
			log("Files still exist in the folder: " + startupDir.getAbsolutePath());
			return false;
		}
		return true;
	}

	public boolean isShutdownRequested()
	{
		return(getShutdownFile().exists());
	}
	
	public boolean canExitNow()
	{
		if( amp.isAmplifierSyncing())
			return false;
		return serverForClients.canExitNow();
	}
	
	public synchronized void incrementFailedUploadRequestsForCurrentClientIp()
	{
		String ip = getCurrentClientIp();
		int failedUploadRequest = 1;
		if(failedUploadRequestsPerIp.containsKey(ip))
		{
			Integer currentValue = (Integer) failedUploadRequestsPerIp.get(ip);
			failedUploadRequest = currentValue.intValue() + failedUploadRequest;
		}
		failedUploadRequestsPerIp.put(ip, new Integer(failedUploadRequest));
	}
	
	public synchronized void subtractMaxFailedUploadRequestsForIp(String ip)
	{
		if(failedUploadRequestsPerIp.containsKey(ip))
		{
			Integer currentValue = (Integer) failedUploadRequestsPerIp.get(ip);
			int newValue = currentValue.intValue() - getMaxFailedUploadAllowedAttemptsPerIp();
			if(newValue < 0)
			{
				failedUploadRequestsPerIp.remove(ip);
			}
			else
			{
				failedUploadRequestsPerIp.put(ip, new Integer(newValue));
			}
		}
	}
	
	public int getMaxFailedUploadAllowedAttemptsPerIp()
	{
		return MAX_FAILED_UPLOAD_ATTEMPTS;
	}
	
	public int getNumFailedUploadRequestsForIp(String ip)
	{
		if(failedUploadRequestsPerIp.containsKey(ip))
		{
			Integer currentValue = (Integer) failedUploadRequestsPerIp.get(ip);
			return currentValue.intValue();
		}
		return 0;
	}
	
	synchronized boolean areUploadRequestsAllowedForCurrentIp()
	{
		String ip = getCurrentClientIp();
		if(failedUploadRequestsPerIp.containsKey(ip))
		{
			return (getNumFailedUploadRequestsForIp(ip) < getMaxFailedUploadAllowedAttemptsPerIp());
		}
		return true;
	}


	protected String getCurrentClientIp()
	{
		String ip;
		Thread currThread = Thread.currentThread();
		if( XmlRpcThread.class.getName() == currThread.getClass().getName() )
		{
			ip = ((XmlRpcThread) Thread.currentThread()).getClientIp();
		}
		else
		{
			ip = Integer.toHexString(currThread.hashCode());
		}

		return ip;
	}
	
	protected String getCurrentClientAddress()
	{
		String ip;
		Thread currThread = Thread.currentThread();
		if( XmlRpcThread.class.getName() == currThread.getClass().getName() )
		{
			ip = ((XmlRpcThread) Thread.currentThread()).getClientAddress();
		}
		else
		{
			ip = Integer.toHexString(currThread.hashCode());
		}

		return ip;
	}

	public synchronized void log(String message)
	{
		getLogger().log(message);
	}
	
	String getServerName()
	{
		if(serverName == null)
			return "host/address";
		return serverName;
	}

	public Vector loadServerPublicKeys(File directoryContainingPublicKeyFiles, String label) throws IOException, InvalidPublicKeyFileException, PublicInformationInvalidException
	{
		Vector servers = new Vector();

		File[] files = directoryContainingPublicKeyFiles.listFiles();
		if(files == null)
			return servers;
		for (int i = 0; i < files.length; i++)
		{
			File thisFile = files[i];
			Vector publicInfo = MartusUtilities.importServerPublicKeyFromFile(thisFile, getSecurity());
			String accountId = (String)publicInfo.get(0);
			servers.add(accountId);
			if(isSecureMode())
			{
				thisFile.delete();
				if(thisFile.exists())
					throw new IOException("delete failed: " + thisFile);
			}
			log(label + " authorized to call us: " + thisFile.getName());
		}
		
		return servers;
	}

	BulletinHeaderPacket loadBulletinHeaderPacket(Database db, DatabaseKey key)
		throws
			IOException,
			CryptoException,
			InvalidPacketException,
			WrongPacketTypeException,
			SignatureVerificationException,
			DecryptionException
	{
		BulletinHeaderPacket bhp = new BulletinHeaderPacket(key.getAccountId());
		InputStreamWithSeek in = db.openInputStream(key, security);
		bhp.loadFromXml(in, security);
		in.close();
		return bhp;
	}

	public class UnexpectedExitException extends Exception{}
	
	public void serverExit(int exitCode) throws UnexpectedExitException 
	{
		System.exit(exitCode);
	}

	abstract class SummaryCollector implements Database.PacketVisitor
	{
		SummaryCollector(Database dbToUse, String accountIdToUse, Vector retrieveTagsToUse)
		{
			db = dbToUse;
			authorAccountId = accountIdToUse;
			retrieveTags = retrieveTagsToUse;
		}
		
		public void visit(DatabaseKey key)
		{
			// TODO: this should only be for maxmaxmaxlogging
//				if(serverMaxLogging)
//				{
//					logging("visit " + 
//						getFolderFromClientId(key.getAccountId()) +  " " +
//						key.getLocalId());
//				}
			if(!BulletinHeaderPacket.isValidLocalId(key.getLocalId()))
			{
				//this would fire for every non-header packet
				//logging("visit  Error:isValidLocalId Key=" + key.getLocalId() );					
				return;
			}
				
			addSummaryIfAppropriate(key);
			return;
		}

		abstract public void addSummaryIfAppropriate(DatabaseKey key);
		
		public Vector getSummaries()
		{
			if(summaries == null)
			{
				summaries = new Vector();
				summaries.add(NetworkInterfaceConstants.OK);
				db.visitAllRecords(this);
			}
			return summaries;	
		}
		
		void addToSummary(BulletinHeaderPacket bhp) 
		{
			String summary = bhp.getLocalId() + "=";
			summary  += bhp.getFieldDataPacketId();
			if(retrieveTags.contains(NetworkInterfaceConstants.TAG_BULLETIN_SIZE))
			{
				int size = MartusUtilities.getBulletinSize(database, bhp);
				summary += "=" + size;
			}
			summaries.add(summary);
		}

		Database db;
		String authorAccountId;
		Vector summaries;
		Vector retrieveTags;
	}
	
	class MySealedSummaryCollector extends SummaryCollector
	{
		public MySealedSummaryCollector(Database dbToUse, String accountIdToUse, Vector retrieveTags) 
		{
			super(dbToUse, accountIdToUse, retrieveTags);
		}

		public void addSummaryIfAppropriate(DatabaseKey key) 
		{
			if(!keyBelongsToClient(key, authorAccountId))
				return;

			if(!key.isSealed())
				return;
				
			try
			{
				addToSummary(loadBulletinHeaderPacket(db, key));
			}
			catch(Exception e)
			{
				log("visit " + e);
				e.printStackTrace();
				//System.out.println("MySealedSummaryCollector: " + e);
			}
		}
	}

	class MyDraftSummaryCollector extends SummaryCollector
	{
		public MyDraftSummaryCollector(Database dbToUse, String accountIdToUse, Vector retrieveTagsToUse) 
		{
			super(dbToUse, accountIdToUse, retrieveTagsToUse);
		}

		public void addSummaryIfAppropriate(DatabaseKey key) 
		{
			if(!keyBelongsToClient(key, authorAccountId))
				return;

			if(!key.isDraft())
				return;

			try
			{
				addToSummary(loadBulletinHeaderPacket(db, key));
			}
			catch(Exception e)
			{
				log("visit " + e);
				e.printStackTrace();
				//System.out.println("MyDraftSummaryCollector: " + e);
			}
		}
	}


	class FieldOfficeSealedSummaryCollector extends SummaryCollector
	{
		public FieldOfficeSealedSummaryCollector(Database dbToUse, String hqAccountIdToUse, String authorAccountIdToUse, Vector retrieveTagsToUse) 
		{
			super(dbToUse, authorAccountIdToUse, retrieveTagsToUse);
			hqAccountId = hqAccountIdToUse;

		}

		public void addSummaryIfAppropriate(DatabaseKey key) 
		{
			if(!keyBelongsToClient(key, authorAccountId))
				return;
			if(!key.isSealed())
				return;
			
			try
			{
				BulletinHeaderPacket bhp = loadBulletinHeaderPacket(db, key);
				if(bhp.getHQPublicKey().equals(hqAccountId))
					addToSummary(bhp);
			}
			catch(Exception e)
			{
				log("visit " + e);
				e.printStackTrace();
				//System.out.println("MartusServer.FieldOfficeSealedSummaryCollectors: " + e);
			}
		}
		String hqAccountId;
	}

	class FieldOfficeDraftSummaryCollector extends SummaryCollector
	{
		public FieldOfficeDraftSummaryCollector(Database dbToUse, String hqAccountIdToUse, String authorAccountIdToUse, Vector retrieveTagsToUse) 
		{
			super(dbToUse, authorAccountIdToUse, retrieveTagsToUse);
			hqAccountId = hqAccountIdToUse;

		}

		public void addSummaryIfAppropriate(DatabaseKey key) 
		{
			if(!keyBelongsToClient(key, authorAccountId))
				return;
			if(!key.isDraft())
				return;
			
			try
			{
				BulletinHeaderPacket bhp = loadBulletinHeaderPacket(db, key);
				if(bhp.getHQPublicKey().equals(hqAccountId))
					addToSummary(bhp);
			}
			catch(Exception e)
			{
				log("visit " + e);
				e.printStackTrace();
				//System.out.println("MartusServer.FieldOfficeDraftSummaryCollectors: " + e);
			}
		}
		String hqAccountId;
	}
	
	public static void writeSyncFile(File syncFile) 
	{
		try 
		{
			FileOutputStream out = new FileOutputStream(syncFile);
			out.write(0);
			out.close();
		} 
		catch(Exception e) 
		{
			System.out.println("MartusServer.main: " + e);
			System.exit(6);
		}
	}
	

	protected char[] getPassphraseFromConsole(MartusServer server)
	{
		System.out.print("Enter passphrase: ");
		System.out.flush();
		
		File waitingFile = new File(server.getTriggerDirectory(), "waiting");
		waitingFile.delete();
		writeSyncFile(waitingFile);
		
		String passphrase = null;
		try
		{
			BufferedReader reader = new BufferedReader(new UnicodeReader(System.in));
			//TODO security issue here password is a string
			passphrase = reader.readLine();
		}
		catch(Exception e)
		{
			System.out.println("MartusServer.main: " + e);
			System.exit(EXIT_UNEXPECTED_EXCEPTION);
		}
		return passphrase.toCharArray();
	}


	private void initializeServerForMirroring() throws Exception
	{
		if(!isMirrorListenerEnabled())
			return;
		serverForMirroring.createGatewaysWeWillCall();
		serverForMirroring.addListeners();
	}

	private void initializeServerForClients() throws UnknownHostException
	{
		if(!isClientListenerEnabled())
			return;
		serverForClients.addListeners();
		serverForClients.displayClientStatistics();
	}
	
	private void initializeServerForAmplifiers() throws UnknownHostException
	{
		if(!isAmplifierListenerEnabled())
			return;
		serverForAmplifiers.addListeners();
	}
	
	public void initalizeAmplifier(char[] keystorePassword) throws Exception
	{
		if(!isAmplifierEnabled())
			return;
		amp.initalizeAmplifier(keystorePassword);
	}

	protected void deleteRunningFile()
	{
		getRunningFile().delete();
	}

	protected File getRunningFile()
	{
		File runningFile = new File(getTriggerDirectory(), "running");
		return runningFile;
	}


	protected static void displayVersion()
	{
		System.out.println("MartusServer");
		System.out.println("Version " + MarketingVersionNumber.marketingVersionNumber);
		String versionInfo = VersionBuildDate.getVersionBuildDate();
		System.out.println("Build Date " + versionInfo);
	}


	public void processCommandLine(String[] args)
	{
		long indexEveryXMinutes = 0;
		String indexEveryXHourTag = "--amplifier-indexing-hours=";
		String indexEveryXMinutesTag = "--amplifier-indexing-minutes=";
		String ampipTag = "--amplifier-ip=";
		String listenersIpTag = "--listeners-ip=";
		String secureModeTag = "--secure";
		String noPasswordTag = "--nopassword";
		String enableAmplifierTag = "--amplifier";
		String enableClientListenerTag = "--client-listener";
		String enableMirrorListenerTag = "--mirror-listener";
		String enableAmplifierListenerTag = "--amplifier-listener";
		String simulateBadConnectionTag = "--simulate-bad-connection";
		
		setAmplifierEnabled(false);
		String amplifierIndexingMessage = "";
		for(int arg = 0; arg < args.length; ++arg)
		{
			String argument = args[arg];
			if(argument.equals(enableAmplifierTag))
				setAmplifierEnabled(true);
			if(argument.equals(enableClientListenerTag))
				setClientListenerEnabled(true);
			if(argument.equals(enableMirrorListenerTag))
				setMirrorListenerEnabled(true);
			if(argument.equals(enableAmplifierListenerTag))
				setAmplifierListenerEnabled(true);
			if(argument.equals(secureModeTag))
				enterSecureMode();
			if(argument.startsWith(listenersIpTag))
				setListenersIpAddress(argument.substring(listenersIpTag.length()));
			if(argument.equals(noPasswordTag))
				insecurePassword = "password".toCharArray();
			if(argument.equals(simulateBadConnectionTag))
				simulateBadConnection = true;
			if(argument.startsWith(ampipTag))
				setAmpIpAddress(argument.substring(ampipTag.length()));

			if(argument.startsWith(indexEveryXHourTag))
			{	
				String hours = argument.substring(indexEveryXHourTag.length());
				amplifierIndexingMessage = "Amplifier indexing every " + hours + " hours";
				long indexEveryXHours = new Integer(hours).longValue();
				indexEveryXMinutes = indexEveryXHours * 60;
			}
			if(argument.startsWith(indexEveryXMinutesTag))
			{	
				String minutes = argument.substring(indexEveryXMinutesTag.length());
				amplifierIndexingMessage = "Amplifier indexing every " + minutes + " minutes";
				indexEveryXMinutes = new Integer(minutes).longValue();
			}
		}
		if(indexEveryXMinutes==0)
		{
			long defaultSyncHours = MartusAmplifier.DEFAULT_HOURS_TO_SYNC;
			indexEveryXMinutes = defaultSyncHours * 60;
			amplifierIndexingMessage = "Amplifier indexing every " + defaultSyncHours + " hours";
		}
		
		
		System.out.println("");
		if(isSecureMode())
			System.out.println("Running in SECURE mode");
		else
			System.out.println("***RUNNING IN INSECURE MODE***");
			
		if(simulateBadConnection)
			System.out.println("***SIMULATING BAD CONNECTIONS!!!***");
		
		if(isClientListenerEnabled())
			System.out.println("Client listener enabled on " + getListenersIpAddress());
		if(isMirrorListenerEnabled())
			System.out.println("Mirror listener enabled on " + getListenersIpAddress());
		if(isAmplifierListenerEnabled())
			System.out.println("Amplifier listener enabled on " + getListenersIpAddress());
		if(isAmplifierEnabled())
		{
			System.out.println("Web Amplifier is Enabled on " + getAmpIpAddress());
			amplifierDataSynchIntervalMillis = indexEveryXMinutes * MINUTES_TO_MILLI;
			System.out.println(amplifierIndexingMessage);
		}
		System.out.println("");
	}

	public static InetAddress getMainIpAddress() throws UnknownHostException
	{
		return InetAddress.getByName(getListenersIpAddress());
	}

	private void initalizeDatabase()
	{
		File dataDirectory = getDataDirectory();
		File packetsDirectory = new File(dataDirectory, "packets");
		Database diskDatabase = new ServerFileDatabase(packetsDirectory, getSecurity());
		try
		{
			diskDatabase.initialize();
		}
		catch(FileDatabase.MissingAccountMapException e)
		{
			e.printStackTrace();
			System.out.println("Missing Account Map File");
			System.exit(7);
		}
		catch(FileDatabase.MissingAccountMapSignatureException e)
		{
			e.printStackTrace();
			System.out.println("Missing Account Map Signature File");
			System.exit(7);
		}
		catch(FileVerificationException e)
		{
			e.printStackTrace();
			System.out.println("Account Map did not verify against signature file");
			System.exit(7);
		}
		
		setDatabase(diskDatabase);
	}

	protected File getKeyPairFile()
	{
		return new File(getStartupConfigDirectory(), getKeypairFilename());
	}

	File getComplianceFile()
	{
		return new File(getStartupConfigDirectory(), COMPLIANCESTATEMENTFILENAME);
	}

	public File getShutdownFile()
	{
		return new File(getTriggerDirectory(), MARTUSSHUTDOWNFILENAME);
	}

	public File getTriggerDirectory()
	{
		return new File(getDataDirectory(), ADMINTRIGGERDIRECTORY);
	}

	public File getStartupConfigDirectory()
	{
		return new File(getDataDirectory(),ADMINSTARTUPCONFIGDIRECTORY);
	}

	private File getHiddenPacketsFile()
	{
		return new File(getStartupConfigDirectory(), HIDDENPACKETSFILENAME);
	}
	
	public void loadHiddenPacketsFile()
	{
		File isHiddenFile = getHiddenPacketsFile();
		try
		{
			UnicodeReader reader = new UnicodeReader(isHiddenFile);
			loadHiddenPacketsList(reader, database, getLogger());
		}
		catch(FileNotFoundException nothingToWorryAbout)
		{
			log("Deleted packets file not found: " + isHiddenFile.getName());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			log("Error loading Deleted Packets file: " + isHiddenFile.getName());
		}
	}

	public static void loadHiddenPacketsList(UnicodeReader reader, Database db, LoggerInterface logger) throws IOException, InvalidBase64Exception
	{
		String accountId = null;
		try
		{
			while(true)
			{
				String thisLine = reader.readLine();
				if(thisLine == null)
					return;
				if(thisLine.startsWith(" "))
					hidePackets(db, accountId, thisLine, logger);
				else
					accountId = thisLine;
			}
		}
		finally
		{
			reader.close();
		}
	}
	
	static void hidePackets(Database db, String accountId, String packetList, LoggerInterface logger) throws InvalidBase64Exception
	{
		String publicCode = MartusCrypto.getFormattedPublicCode(accountId);
		String[] packetIds = packetList.trim().split("\\s+");
		for (int i = 0; i < packetIds.length; i++)
		{
			String localId = packetIds[i].trim();
			UniversalId uid = UniversalId.createFromAccountAndLocalId(accountId, localId);
			db.hide(uid);
			logger.log("Deleting " + publicCode + ": " + localId);
		}
	}
	
	public File getDataDirectory()
	{
		return dataDirectory;
	}

	private class UploadRequestsMonitor extends TimerTask
	{
		public void run()
		{
			Iterator failedUploadReqIps = failedUploadRequestsPerIp.keySet().iterator();
			while(failedUploadReqIps.hasNext())
			{
				String ip = (String) failedUploadReqIps.next();
				subtractMaxFailedUploadRequestsForIp(ip);
			}
		}
	}
	
	class SyncAmplifierWithServersMonitor extends TimerTask
	{	
		public void run()
		{
			if(! amp.isAmplifierSyncing() )
			{
				amp.startSynch();
				amp.pullNewDataFromServers(amp.backupServersList);
				amp.endSynch();
			}
		}
	}

	private class ShutdownRequestMonitor extends TimerTask
	{
		public void run()
		{
			if( isShutdownRequested() && canExitNow() )
			{
				log("Shutdown request received.");
				
				serverForClients.prepareToShutdown();				
				getShutdownFile().delete();
				log("Server has exited.");
				try
				{
					serverExit(0);
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		}
	}

	public MartusCrypto security;

	ServerForMirroring serverForMirroring;
	public ServerForClients serverForClients;
	public ServerForAmplifiers serverForAmplifiers;
	public MartusAmplifier amp;
	private boolean amplifierEnabled;
	private boolean clientListenerEnabled;
	private boolean mirrorListenerEnabled;
	private boolean amplifierListenerEnabled;
	
	private File dataDirectory;
	protected Database database;
	private String complianceStatement; 
	
	Hashtable failedUploadRequestsPerIp;
	
	private LoggerInterface logger;
	String serverName;
	
	private boolean secureMode;
	private static String listenersIpAddress; 
	private String ampIpAddress;
	public boolean simulateBadConnection;

	public char[] insecurePassword;
	public long amplifierDataSynchIntervalMillis;
	
	private static final int EXIT_CRYPTO_INITIALIZATION = 1;
	private static final int EXIT_KEYPAIR_FILE_MISSING = 2;
	private static final int EXIT_UNEXPECTED_EXCEPTION = 3;
	private static final int EXIT_UNEXPECTED_FILE_STARTUP = 4;
	private static final int EXIT_STARTUP_DIRECTORY_NOT_EMPTY = 5;
	private static final int EXIT_NO_LISTENERS = 20;
	private static final int EXIT_INVALID_IPADDRESS = 23;
	private static final int EXIT_INVALID_PASSWORD = 73;
	
	private static final String KEYPAIRFILENAME = "keypair.dat";
	private static final String HIDDENPACKETSFILENAME = "isHidden.txt";
	private static final String COMPLIANCESTATEMENTFILENAME = "compliance.txt";
	private static final String MARTUSSHUTDOWNFILENAME = "exit";
	
	private static final String ADMINTRIGGERDIRECTORY = "adminTriggers";
	private static final String ADMINSTARTUPCONFIGDIRECTORY = "deleteOnStartup";
	
	private final int MAX_FAILED_UPLOAD_ATTEMPTS = 100;
	private static final long magicWordsGuessIntervalMillis = 60 * 1000;
	private static final long shutdownRequestIntervalMillis = 1000;
	private static final long MINUTES_TO_MILLI = 60 * 1000;
}
