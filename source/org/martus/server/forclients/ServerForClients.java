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

package org.martus.server.forclients;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Vector;

import org.martus.common.MartusUtilities;
import org.martus.common.MartusUtilities.FileVerificationException;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.network.MartusXmlRpcServer;
import org.martus.common.network.NetworkInterfaceXmlRpcConstants;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.server.main.MartusServer;
import org.martus.util.UnicodeWriter;
import org.martus.util.xmlrpc.WebServerWithClientId;

public class ServerForClients implements ServerForNonSSLClientsInterface, ServerForClientsInterface
{
	public ServerForClients(MartusServer coreServerToUse)
	{
		coreServer = coreServerToUse;
		magicWords = new MagicWords(coreServer);
		clientsThatCanUpload = new Vector();
		activeWebServers = new Vector();
	}
	
	public MartusCrypto getSecurity()
	{
		return coreServer.getSecurity();
	}
	
	public String getPublicCode(String clientId)
	{
		return coreServer.getPublicCode(clientId); 
	}
	
	public void addListeners() throws UnknownHostException
	{
		log("Initializing ServerForClients");
		handleSSL(NetworkInterfaceXmlRpcConstants.defaultSSLPorts);
		handleNonSSL(NetworkInterfaceXmlRpcConstants.defaultNonSSLPorts);
		log("Client ports opened");
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
		System.out.println(magicWords.size() + " active magic word(s)");
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
		return (getNumberActiveClients() == 0);
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
	public String deleteDraftBulletins(String accountId, String[] localIds)
	{
		return coreServer.deleteDraftBulletins(accountId, localIds);
	}

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

	public Vector listMySealedBulletinIds(String authorAccountId, Vector retrieveTags)
	{
		return coreServer.listMySealedBulletinIds(authorAccountId, retrieveTags);
	}

	public String putBulletinChunk(String myAccountId, String authorAccountId, String bulletinLocalId, int totalSize, int chunkOffset, int chunkSize, String data)
	{
		return coreServer.putBulletinChunk(myAccountId, authorAccountId, bulletinLocalId, totalSize, chunkOffset, chunkSize, data);
	}

	public String putContactInfo(String myAccountId, Vector parameters)
	{
		return coreServer.putContactInfo(myAccountId, parameters);
	}

	public Vector listFieldOfficeDraftBulletinIds(String hqAccountId, String authorAccountId, Vector retrieveTags)
	{
		return coreServer.listFieldOfficeDraftBulletinIds(hqAccountId, authorAccountId, retrieveTags);
	}

	public Vector listFieldOfficeSealedBulletinIds(String hqAccountId, String authorAccountId, Vector retrieveTags)
	{
		return coreServer.listFieldOfficeSealedBulletinIds(hqAccountId, authorAccountId, retrieveTags);
	}

	public Vector listMyDraftBulletinIds(String authorAccountId, Vector retrieveTags)
	{
		return coreServer.listMyDraftBulletinIds(authorAccountId, retrieveTags);
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
		return coreServer.requestUploadRights(clientId, tryMagicWord);
	}
	
	public Vector listFieldOfficeAccounts(String hqAccountId)
	{
		return coreServer.listFieldOfficeAccounts(hqAccountId);
	}
	
	File getBannedFile()
	{
		return new File(coreServer.getStartupConfigDirectory(), BANNEDCLIENTSFILENAME);
	}

	public synchronized void loadBannedClients()
	{
		loadBannedClients(getBannedFile());
	}
	
	public void loadBannedClients(File bannedClientsFile)
	{
		clientsBanned = new Vector();
		if(!bannedClientsFile.exists())
			return;
		try
		{
			clientsBanned = MartusUtilities.loadListFromFile(bannedClientsFile);
		}
		catch (IOException e)
		{
			e.printStackTrace();
			System.exit(12);
		}
	}

	public void deleteBannedFile()
	{
		if(getBannedFile().exists())
		{
			if(!getBannedFile().delete())
			{
				System.out.println("Unable to delete " + getBannedFile().getAbsolutePath() );
				System.exit(5);
			}
		}
	}

	public boolean isValidMagicWord(String tryMagicWord)
	{
		return (magicWords.isValidMagicWord(tryMagicWord));
	}
	
	public void addMagicWord(String newMagicWordInfo)
	{
		magicWords.add(newMagicWordInfo);
	}
	
	public File getMagicWordsFile()
	{
		return new File(coreServer.getStartupConfigDirectory(), MAGICWORDSFILENAME);
	}

	void loadMagicWordsFile() throws IOException
	{
		magicWords.loadMagicWords(getMagicWordsFile());
	}

	public void deleteMagicWordsFile()
	{
		if(!getMagicWordsFile().delete())
		{
			System.out.println("Unable to delete magicwords");
			System.exit(4);
		}
	}

	public synchronized void allowUploads(String clientId)
	{
		log("allowUploads " + coreServer.getClientAliasForLogging(clientId) + " : " + getPublicCode(clientId));
		clientsThatCanUpload.add(clientId);
		
		try
		{
			UnicodeWriter writer = new UnicodeWriter(getAllowUploadFile(), UnicodeWriter.APPEND);
			writer.writeln(clientId);
			writer.close();
			MartusCrypto security = getSecurity();
			MartusServerUtilities.createSignatureFileFromFileOnServer(getAllowUploadFile(), security);
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

	void loadCanUploadFile()
	{
		try
		{
			BufferedReader reader = new BufferedReader(new FileReader(getAllowUploadFile()));
			loadCanUploadList(reader);
			reader.close();
		}
		catch(FileNotFoundException nothingToWorryAbout)
		{
		}
		catch(IOException e)
		{
			// TODO: Log this so the administrator knows
			System.out.println("MartusServer constructor: " + e);
		}
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
	

	MartusServer coreServer;
	private int activeClientsCounter;
	MagicWords magicWords;
	
	public Vector clientsThatCanUpload;
	public Vector clientsBanned;
	private Vector activeWebServers;

	private static final String BANNEDCLIENTSFILENAME = "banned.txt";
	private static final String MAGICWORDSFILENAME = "magicwords.txt";
	private static final String UPLOADSOKFILENAME = "uploadsok.txt";
}
