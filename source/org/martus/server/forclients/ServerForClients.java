/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002-2004, Beneficent
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

package org.martus.server.forclients;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Vector;

import org.martus.common.MagicWordEntry;
import org.martus.common.MagicWords;
import org.martus.common.MartusUtilities;
import org.martus.common.Version;
import org.martus.common.MartusUtilities.FileVerificationException;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.database.DatabaseKey;
import org.martus.common.network.MartusXmlRpcServer;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.network.NetworkInterfaceXmlRpcConstants;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.server.main.MartusServer;
import org.martus.server.main.ServerBulletinStore;
import org.martus.util.UnicodeWriter;
import org.martus.util.inputstreamwithseek.InputStreamWithSeek;
import org.martus.util.xmlrpc.WebServerWithClientId;


public class ServerForClients implements ServerForNonSSLClientsInterface, ServerForClientsInterface
{
	public ServerForClients(MartusServer coreServerToUse)
	{
		coreServer = coreServerToUse;
		magicWords = new MagicWords(coreServer.getLogger());
		clientsThatCanUpload = new Vector();
		activeWebServers = new Vector();
		loggedNumberOfActiveClients = 0;
	}
	
	public Vector getDeleteOnStartupFiles()
	{
		Vector startupFiles = new Vector();
		startupFiles.add(getMagicWordsFile());
		startupFiles.add(getBannedFile());
		startupFiles.add(getTestAccountsFile());
		return startupFiles;
	}
	
	public void deleteStartupFiles()
	{
		MartusUtilities.deleteAllFiles(getDeleteOnStartupFiles());
	}
	
	public ServerBulletinStore getStore()
	{
		return coreServer.getStore();
	}
	
	public MartusCrypto getSecurity()
	{
		return coreServer.getSecurity();
	}
	
	public String getPublicCode(String clientId)
	{
		return coreServer.getPublicCode(clientId); 
	}
	
	private File getConfigDirectory()
	{
		return coreServer.getStartupConfigDirectory();
	}

	public void addListeners() throws UnknownHostException
	{
		log("Initializing ServerForClients");
		handleSSL(getSSLPorts());
		handleNonSSL(getNonSSLPorts());
		log("Client ports opened");
	}
	
	private int[] getNonSSLPorts()
	{
		int[] defaultPorts = NetworkInterfaceXmlRpcConstants.defaultNonSSLPorts;
		return shiftToDevelopmentPortsIfRequested(defaultPorts);
	}

	private int[] getSSLPorts()
	{
		int[] defaultPorts = NetworkInterfaceXmlRpcConstants.defaultSSLPorts;
		return shiftToDevelopmentPortsIfRequested(defaultPorts);
	}

	public int[] shiftToDevelopmentPortsIfRequested(int[] defaultPorts)
	{
		if(isRunningUnderWindows())
			return defaultPorts;
		
		if(!wantsDevelopmentMode())
			return defaultPorts;
		
		int[] developmentPorts = new int[defaultPorts.length];
		for(int p = 0; p < developmentPorts.length; ++p)
			developmentPorts[p] = defaultPorts[p] + 9000;
		
		return developmentPorts;
	}

	boolean wantsDevelopmentMode()
	{
		if(MartusServer.class.getResource("ForceListenOnNonPrivilegedPorts.txt") == null)
			return false;
		
		log("*********************************************");
		log("WARNING: Development mode selected;");
		log("         Using non-privileged ports!");
		log("*********************************************");
		return true;
	}

	boolean isRunningUnderWindows()
	{
		return Version.isRunningUnderWindows();
	}

	public synchronized void log(String message)
	{
		coreServer.log(message);
	}
	
	public void displayClientStatistics()
	{
		System.out.println();
		System.out.println(clientsThatCanUpload.size() + " client(s) currently allowed to upload");
		System.out.println(clientsBanned.size() + " client(s) are currently banned");
		System.out.println(magicWords.getNumberOfActiveWords() + " active magic word(s)");
		System.out.println(magicWords.getNumberOfInactiveWords() + " inactive magic word(s)");
		System.out.println(getNumberOfTestAccounts() + " client(s) are known test accounts");
		System.out.println();
	}

	public void verifyConfigurationFiles()
	{
		try
		{
			File allowUploadFileSignature = MartusServerUtilities.getLatestSignatureFileFromFile(getAllowUploadFile());
			MartusCrypto security = getSecurity();
			MartusServerUtilities.verifyFileAndSignatureOnServer(getAllowUploadFile(), allowUploadFileSignature, security, security.getPublicKeyString());
		}
		catch(FileVerificationException e)
		{
			e.printStackTrace();
			System.out.println(UPLOADSOKFILENAME + " did not verify against signature file");
			System.exit(7);
		}
		catch(Exception e)
		{
			if(getAllowUploadFile().exists())
			{
				e.printStackTrace();
				System.out.println("Unable to verify " + UPLOADSOKFILENAME + " against a signature file");
				System.exit(7);
			}
		}
	}

	public void loadConfigurationFiles() throws IOException
	{
		loadBannedClients();
		loadCanUploadFile();
		loadMagicWordsFile();
		loadTestAccounts();
	}

	public void prepareToShutdown()
	{
		clearCanUploadList();
		for(int i = 0 ; i < activeWebServers.size(); ++i)
		{
			WebServerWithClientId server = (WebServerWithClientId)(activeWebServers.get(i));
			if(server != null)
				server.shutdown();
		}
	}

	public boolean isClientBanned(String clientId)
	{
		if(clientsBanned.contains(clientId))
		{
			log("client BANNED: " + getPublicCode(clientId));
			return true;
		}
		return false;
	}
	
	public boolean isTestAccount(String clientId)
	{
		if(testAccounts.contains(clientId))
			return true;
		return false;
	}
	
	public int getNumberOfTestAccounts()
	{
		return testAccounts.size();
	}
	
	public boolean canClientUpload(String clientId)
	{
		if(!clientsThatCanUpload.contains(clientId))
		{
			log("client NOT AUTHORIZED: " + getPublicCode(clientId));
			return false;
		}
		return true;
	}
	
	public void clearCanUploadList()
	{
		clientsThatCanUpload.clear();
	}
	

	public boolean canExitNow()
	{
		int numberActiveClients = getNumberActiveClients();
		if(numberActiveClients != 0 && loggedNumberOfActiveClients != numberActiveClients)
		{	
			log("Unable to exit, number of active clients =" + numberActiveClients);
			loggedNumberOfActiveClients = numberActiveClients;
		}
		return (numberActiveClients == 0);
	}
	
	synchronized int getNumberActiveClients()
	{
		return activeClientsCounter;
	}
	
	
	public synchronized void clientConnectionStart()
	{
		activeClientsCounter++;
	}
	
	public synchronized void clientConnectionExit()
	{
		activeClientsCounter--;
	}
	
	public boolean shouldSimulateBadConnection()
	{
		return coreServer.simulateBadConnection;
	}
	
	public void handleNonSSL(int[] ports) throws UnknownHostException
	{
		ServerSideNetworkHandlerForNonSSL nonSSLServerHandler = new ServerSideNetworkHandlerForNonSSL(this);
		for(int i=0; i < ports.length; ++i)
		{	
			InetAddress mainIpAddress = MartusServer.getMainIpAddress();
			log("Opening NonSSL port " + mainIpAddress +":" + ports[i] + " for clients...");
			activeWebServers.add(MartusXmlRpcServer.createNonSSLXmlRpcServer(nonSSLServerHandler, "MartusServer", ports[i], mainIpAddress));
		}
	}
	
	public void handleSSL(int[] ports) throws UnknownHostException
	{
		ServerSideNetworkHandler serverHandler = new ServerSideNetworkHandler(this);
		for(int i=0; i < ports.length; ++i)
		{	
			InetAddress mainIpAddress = MartusServer.getMainIpAddress();
			log("Opening SSL port " + mainIpAddress +":" + ports[i] + " for clients...");
			activeWebServers.add(MartusXmlRpcServer.createSSLXmlRpcServer(serverHandler, "MartusServer", ports[i], mainIpAddress));
		}
	}


	// BEGIN SSL interface
	public Vector getBulletinChunk(String myAccountId, String authorAccountId, String bulletinLocalId, int chunkOffset, int maxChunkSize)
	{
		return coreServer.getBulletinChunk(myAccountId, authorAccountId, bulletinLocalId, chunkOffset, maxChunkSize);
	}

	public Vector getNews(String myAccountId, String versionLabel, String versionBuildDate)
	{
		return coreServer.getNews(myAccountId, versionLabel, versionBuildDate);
	}

	public Vector getPacket(String myAccountId, String authorAccountId, String bulletinLocalId, String packetLocalId)
	{
		return coreServer.getPacket(myAccountId, authorAccountId, bulletinLocalId, packetLocalId);
	}

	public Vector getServerCompliance()
	{
		return coreServer.getServerCompliance();
	}

	public String putBulletinChunk(String myAccountId, String authorAccountId, String bulletinLocalId, int totalSize, int chunkOffset, int chunkSize, String data)
	{
		return coreServer.putBulletinChunk(myAccountId, authorAccountId, bulletinLocalId, totalSize, chunkOffset, chunkSize, data);
	}

	public String putContactInfo(String myAccountId, Vector parameters)
	{
		return coreServer.putContactInfo(myAccountId, parameters);
	}

	public Vector listMySealedBulletinIds(String myAccountId, Vector retrieveTags)
	{
		SummaryCollector summaryCollector = new MySealedSummaryCollector(coreServer, myAccountId, retrieveTags);
		return collectBulletinSummaries(summaryCollector, "listMySealedBulletinIds ");
	}

	public Vector listFieldOfficeDraftBulletinIds(String hqAccountId, String authorAccountId, Vector retrieveTags)
	{
		SummaryCollector summaryCollector = new FieldOfficeDraftSummaryCollector(coreServer, hqAccountId, authorAccountId, retrieveTags);
		return collectBulletinSummaries(summaryCollector, "listFieldOfficeDraftBulletinIds ");
	}

	public Vector listFieldOfficeSealedBulletinIds(String hqAccountId, String authorAccountId, Vector retrieveTags)
	{
		SummaryCollector summaryCollector = new FieldOfficeSealedSummaryCollector(coreServer, hqAccountId, authorAccountId, retrieveTags);
		return collectBulletinSummaries(summaryCollector, "listFieldOfficeSealedBulletinIds ");
	}

	public Vector listMyDraftBulletinIds(String authorAccountId, Vector retrieveTags)
	{
		SummaryCollector summaryCollector = new MyDraftSummaryCollector(coreServer, authorAccountId, retrieveTags);
		return collectBulletinSummaries(summaryCollector, "listMyDraftBulletinIds");
	}

	public String deleteDraftBulletins(String accountId, String[] localIds)
	{
		if(isClientBanned(accountId) )
			return NetworkInterfaceConstants.REJECTED;
		
		if( coreServer.isShutdownRequested() )
			return NetworkInterfaceConstants.SERVER_DOWN;
			
		String result = NetworkInterfaceConstants.OK;
		for (int i = 0; i < localIds.length; i++)
		{
			UniversalId uid = UniversalId.createFromAccountAndLocalId(accountId, localIds[i]);
			try
			{
				// TODO: reading the bhp protects us from trying to delete a sealed bulletin
				// instead, the store should offer helpers to do this without having to 
				// read the bhp at all
				DatabaseKey key = DatabaseKey.createDraftKey(uid);
				BulletinHeaderPacket bhp = new BulletinHeaderPacket(uid);
				InputStreamWithSeek in = coreServer.getDatabase().openInputStream(key, getSecurity());
				bhp.loadFromXml(in, null, getSecurity());
				in.close();
		
				getStore().deleteBulletinRevision(key);
			}
			catch (Exception e)
			{
				log("deleteDraftBulletins: " + e);
				result = NetworkInterfaceConstants.INCOMPLETE;
			}
		}
		return result;
	}

	public Vector listFieldOfficeAccounts(String hqAccountId)
	{
		return coreServer.listFieldOfficeAccounts(hqAccountId);
	}
	
	// begin NON-SSL interface (sort of)
	public String authenticateServer(String tokenToSign)
	{
		return coreServer.authenticateServer(tokenToSign);
	}

	public String ping()
	{
		return coreServer.ping();
	}
	
	public Vector getServerInformation()
	{
		return coreServer.getServerInformation();
	}
	
	public String requestUploadRights(String clientId, String tryMagicWord)
	{
		boolean uploadGranted = false;
		
		if(isValidMagicWord(tryMagicWord))
			uploadGranted = true;
			
		if(!coreServer.areUploadRequestsAllowedForCurrentIp())
		{
			if(!uploadGranted)
				coreServer.incrementFailedUploadRequestsForCurrentClientIp();
			return NetworkInterfaceConstants.SERVER_ERROR;
		}
		
		if( coreServer.isClientBanned(clientId) )
			return NetworkInterfaceConstants.REJECTED;
			
		if( coreServer.isShutdownRequested() )
			return NetworkInterfaceConstants.SERVER_DOWN;
			
		if(tryMagicWord.length() == 0 && coreServer.canClientUpload(clientId))
			return NetworkInterfaceConstants.OK;
		
		if(!uploadGranted)
		{
			coreServer.log("requestUploadRights: Rejected " + coreServer.getPublicCode(clientId) + " tryMagicWord=" +tryMagicWord);
			coreServer.incrementFailedUploadRequestsForCurrentClientIp();
			return NetworkInterfaceConstants.REJECTED;
		}
		
		allowUploads(clientId, tryMagicWord);
		return NetworkInterfaceConstants.OK;
	}
	

	
	
	
	
	
	private Vector collectBulletinSummaries(SummaryCollector summaryCollector, String methodName)
	{
		String myAccountId = summaryCollector.callerAccountId();
		log(methodName + coreServer.getClientAliasForLogging(myAccountId));
		
		if(isClientBanned(myAccountId) )
			return coreServer.returnSingleResponseAndLog("  returning REJECTED", NetworkInterfaceConstants.REJECTED);
		
		if( coreServer.isShutdownRequested() )
			return coreServer.returnSingleResponseAndLog( " returning SERVER_DOWN", NetworkInterfaceConstants.SERVER_DOWN );
		
		Vector summaries = summaryCollector.collectSummaries();
		Vector result = new Vector();
		result.add(NetworkInterfaceConstants.OK);
		result.add(summaries);
		
		log(methodName + "Exit");
		return result;
	}

	File getBannedFile()
	{
		return new File(getConfigDirectory(), BANNEDCLIENTSFILENAME);
	}
	
	File getTestAccountsFile()
	{
		return new File(getConfigDirectory(), TESTACCOUNTSFILENAME);
	}

	public synchronized void loadBannedClients()
	{
		loadBannedClients(getBannedFile());
	}
	
	public void loadBannedClients(File bannedClientsFile)
	{
		clientsBanned = MartusUtilities.loadClientListAndExitOnError(bannedClientsFile);
	}	
	
	public synchronized void loadTestAccounts()
	{
		loadTestAccounts(getTestAccountsFile());
	}
	
	public void loadTestAccounts(File testAccountsFile)
	{
		testAccounts = MartusUtilities.loadClientListAndExitOnError(testAccountsFile);
	}	
	
	public String getGroupNameForMagicWord(String tryMagicWord)
	{
		MagicWordEntry entry = magicWords.getMagicWordEntry(tryMagicWord);
		if(entry==null)
			return "";
		return entry.getGroupName();
	}

	public String getHumanReadableMagicWord(String magicWordToUse)
	{
		MagicWordEntry entry = magicWords.getMagicWordEntry(magicWordToUse);
		if(entry==null)
			return "";
		return entry.getMagicWord();
	}
	
	public boolean isValidMagicWord(String magicWordToUse)
	{
		return (magicWords.isValidMagicWord(magicWordToUse));
	}
	
	public void addMagicWordForTesting(String newMagicWordInfo, String groupInfo)
	{
		magicWords.add(newMagicWordInfo, groupInfo);
	}
	
	public File getMagicWordsFile()
	{
		return new File(getConfigDirectory(), MAGICWORDSFILENAME);
	}

	void loadMagicWordsFile() throws IOException
	{
		magicWords.loadMagicWords(getMagicWordsFile());
	}

	public synchronized void allowUploads(String clientId, String magicWordUsed)
	{
		String magicWord = getHumanReadableMagicWord(magicWordUsed);
		String groupName = getGroupNameForMagicWord(magicWordUsed);
		
		log("allowUploads granted to: " + coreServer.getClientAliasForLogging(clientId) + " : " + clientId + " groupName= " + groupName + " with magicword=" + magicWord);
		clientsThatCanUpload.add(clientId);
		
		try
		{
			UnicodeWriter writer = new UnicodeWriter(getAllowUploadFile(), UnicodeWriter.APPEND);
			writer.writeln(clientId);
			writer.close();
			MartusCrypto security = getSecurity();
			MartusServerUtilities.createSignatureFileFromFileOnServer(getAllowUploadFile(), security);
			
			AuthorizeLog authorizeLog = new AuthorizeLog(security, coreServer.getLogger(), getAuthorizeLogFile());
			String publicCode = getPublicCode(clientId);
			authorizeLog.appendToFile(new AuthorizeLogEntry(publicCode, groupName));

			log("allowUploads : Exit OK");
		}
		catch(Exception e)
		{
			log("allowUploads " + e);
			//System.out.println("MartusServer.allowUploads: " + e);
			
			//TODO: Should report error back to user. Shouldn't update in-memory list
			// (clientsThatCanUpload) until AFTER the file has been written
		}
	}

	public File getAllowUploadFile()
	{
		return new File(coreServer.getDataDirectory(), UPLOADSOKFILENAME);
	}
	
	public File getAuthorizeLogFile()
	{
		return new File(coreServer.getDataDirectory(), AUTHORIZELOGFILENAME);
	}

	void loadCanUploadFile()
	{
		log("loadCanUploadList");
		clientsThatCanUpload = MartusUtilities.loadClientList(getAllowUploadFile());
	}
	
	public synchronized void loadCanUploadList(BufferedReader canUploadInput)
	{
		log("loadCanUploadList");

		try
		{
			clientsThatCanUpload = MartusUtilities.loadListFromFile(canUploadInput);
		}
		catch (IOException e)
		{
			log("loadCanUploadList -- Error loading can-upload list: " + e);
			clientsThatCanUpload = new Vector();
		}
		
		log("loadCanUploadList : Exit OK");
	}
	
	abstract class MySummaryCollector extends SummaryCollector
	{
		public MySummaryCollector(MartusServer serverToUse, String authorAccount, Vector retrieveTags) 
		{
			super(serverToUse, authorAccount, retrieveTags);
		}

		public boolean isAuthorized(BulletinHeaderPacket bhp)
		{
			return true;
		}

		public String callerAccountId()
		{
			return authorAccountId;
		}
	
	}
	

	class MySealedSummaryCollector extends MySummaryCollector
	{
		public MySealedSummaryCollector(MartusServer serverToUse, String authorAccount, Vector retrieveTags) 
		{
			super(serverToUse, authorAccount, retrieveTags);
		}

		public boolean isWanted(DatabaseKey key)
		{
			return(key.isSealed());
		}
	}

	class MyDraftSummaryCollector extends MySummaryCollector
	{
		public MyDraftSummaryCollector(MartusServer serverToUse, String authorAccount, Vector retrieveTagsToUse) 
		{
			super(serverToUse, authorAccount, retrieveTagsToUse);
		}

		public boolean isWanted(DatabaseKey key)
		{
			return(key.isDraft());
		}
	}
	
	
	
	abstract class FieldOfficeSummaryCollector extends SummaryCollector
	{
		public FieldOfficeSummaryCollector(MartusServer serverToUse, String hqAccountIdToUse, String authorAccountIdToUse, Vector retrieveTagsToUse) 
		{
			super(serverToUse, authorAccountIdToUse, retrieveTagsToUse);
			hqAccountId = hqAccountIdToUse;

		}
		
		String hqAccountId;

		public boolean isAuthorized(BulletinHeaderPacket bhp)
		{
			return(bhp.isHQAuthorizedToRead(hqAccountId));
		}

		public String callerAccountId()
		{
			return hqAccountId;
		}
	}

	class FieldOfficeSealedSummaryCollector extends FieldOfficeSummaryCollector
	{
		public FieldOfficeSealedSummaryCollector(MartusServer serverToUse, String hqAccountIdToUse, String authorAccountIdToUse, Vector retrieveTagsToUse) 
		{
			super(serverToUse, hqAccountIdToUse, authorAccountIdToUse, retrieveTagsToUse);
		}

		public boolean isWanted(DatabaseKey key)
		{
			return(key.isSealed());
		}
	}

	class FieldOfficeDraftSummaryCollector extends FieldOfficeSummaryCollector
	{
		public FieldOfficeDraftSummaryCollector(MartusServer serverToUse, String hqAccountIdToUse, String authorAccountIdToUse, Vector retrieveTagsToUse) 
		{
			super(serverToUse, hqAccountIdToUse, authorAccountIdToUse, retrieveTagsToUse);
		}

		public boolean isWanted(DatabaseKey key)
		{
			return(key.isDraft());
		}
	}

	MartusServer coreServer;
	private int activeClientsCounter;
	private int loggedNumberOfActiveClients;
	MagicWords magicWords;
	
	public Vector clientsThatCanUpload;
	public Vector clientsBanned;
	public Vector testAccounts;
	private Vector activeWebServers;
	public static final String TESTACCOUNTSFILENAME = "isTester.txt";
	public static final String BANNEDCLIENTSFILENAME = "banned.txt";
	public static final String UPLOADSOKFILENAME = "uploadsok.txt";
	public static final String AUTHORIZELOGFILENAME = "authorizelog.txt";
	private static final String MAGICWORDSFILENAME = "magicwords.txt";
}
